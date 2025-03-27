from abc import ABC, abstractmethod
from tor_encrypt import encrypt, decrypt, generate_prime_number

EXTEND_PREFIX = b"EXTEND:" # EXTEND:id,p,g,A
EXTEND_REPLY_PREFIX = b"EXTRPY:" # EXTRPY:B
SERVER_ID = -1
CLIENT_ID = 0

# Payload of command to extend circuit with diffie-hellman parameters
def compose_extend_msg(id, p, g, A):
    return EXTEND_PREFIX + str.encode(str(id)+","+str(p)+","+str(g)+","+str(A))

# Payload for diffie hellman reply handshake
def compose_extend_reply_msg(B):
    return EXTEND_REPLY_PREFIX + str.encode(str(B))


def parse_extend_msg(msg):
    if not msg.startswith(EXTEND_PREFIX):
        print("ERROR: Cannot parse extend message!")
        return
    content = msg[len(EXTEND_PREFIX):].split(b",")
    return [int(x) for x in content]

def parse_extend_reply(msg):
    if not msg.startswith(EXTEND_REPLY_PREFIX):
        print("ERROR: Cannot parse extend reply message!")
        return
    content = msg[len(EXTEND_REPLY_PREFIX):].split(b",")
    return [int(x) for x in content]


class DirectoryAuthoritiy:
    """
    Simple Directory Authority with list of relays.
    """
    entry_relays = []
    middle_relays = []
    exit_relays = []
    def maintain_consensus(self):
        """Consensus simplified"""
        self.entry_relays = [Relay(1), Relay(2)]
        self.middle_relays = [Relay(3), Relay(4)]
        self.exit_relays = [Relay(5), Relay(6)]
        pass

    def find_relay(self, id):
        """Finds the relay with id, or the server is the server is provided"""
        # Directly connect to server (for exit relay)
        if id == SERVER_ID:
            return server
        return [relay for relay in self.entry_relays + self.middle_relays + self.exit_relays if relay.id == id][0]

    def get_circuit_ids(self):
        """Use these three relays for simplicity"""
        return [1,3,5]


class EncryptorDecryptor(ABC):
    id = None
    @abstractmethod
    def receive(self, msg, sender):
        pass

    def send_payload(self, msg, target):
        target.receive(msg,self)

class Relay(EncryptorDecryptor):
    """
    A TOR Relay with some given id.
    - prev: Next relay towards the Client, or the Client itself
    - next: Next relay towards the Server, or the Server itself
    - key: Diffie-hellman key that is shared with Client
    """
    prev = None
    next = None
    key = None

    b = 0
    B = 0

    def __init__(self, id):
        self.id = id

    def generate_diff_hell_nums(self, p, g):
        """Generate diffie-hellman primes and public key"""
        self.b = generate_prime_number()
        self.B = (g ** self.b) % p

    def getKey(self, msg):
        """Gets shared secret from client's public key"""
        content = parse_extend_msg(msg)
        if not content:
                return None
        _, p, g, A = content
        self.generate_diff_hell_nums(p, g)
        return (A**self.b) % p

    def receive(self, msg, sender):
        """Handler for key-exchange or circuit extension"""

        if msg.startswith(EXTEND_PREFIX) and sender == self.prev:
            self.key = self.getKey(msg)
            reply_msg = compose_extend_reply_msg(self.B)

            # TODO: Send diffie-hellman reply message to previous hop
            # Hint: No encryption needed
            self.send_payload(reply_msg, self.prev)

        elif sender == self.next:

            # TODO: Encrypt payload and send it to previous hop
            encrypted_msg = encrypt(msg, self.key)
            self.send_payload(encrypted_msg, self.prev)

        elif sender == self.prev:
            decrypted_msg = decrypt(msg, self.key)

            # Or decrypted_msg.startswith(EXTEND_PREFIX)

            # Case for circuit extension
            if self.next is None:
                content = parse_extend_msg(decrypted_msg)
                if not content:
                    return
                next_id, _, _, _= content

                # TODO: Connect to next relay/hop
                self.next = authority.find_relay(next_id)
                self.next.prev = self

            if self.next != server or not decrypted_msg.startswith(EXTEND_PREFIX):

                # TODO: Send decrypted message to next hop
                self.send_payload(decrypted_msg, self.next)
            else:
                # Drop the diffie-hellman exchange signal,
                # As we do not do the exchange with the server
                pass

class Server(EncryptorDecryptor):
    """
    Simple server that sends a single response
    """
    id = SERVER_ID
    def receive(self, msg, sender):
        print(b"SERVER received: "+msg)
        self.send_payload(b"Congrats for completing CSC427!!", sender)


class Client(EncryptorDecryptor):
    """
    TOR Client
    - entry_relay: Connection to entry relay
    - k_xxx: diffie-hellman keys for relays
    - circuit_setup: Flag to determine whether circuit is successfully set up
    - tor_relays: Ids of relays that make up a circuit

    """
    id = CLIENT_ID
    entry_relay = None
    k_entry = None
    k_middle = None
    k_exit = None
    circuit_setup = False
    tor_relays = []

    # Diffie-hellman key exchange prime numbers
    a = 0
    p = 0
    g = 0
    A = 0

    def generate_diff_hell_nums(self):
        """Generate primes and public key for diffie-hellman key exchange"""
        self.p=generate_prime_number()
        self.a=generate_prime_number()
        self.g=generate_prime_number()
        self.A=(self.g**self.a) % self.p

    def get_key(self, msg):
        """Gets shared secret from Server's public key message"""
        content = parse_extend_reply(msg)
        if not content:
            return None
        B = content[0]
        ret = (B**self.a) % self.p
        return ret

    def receive(self, msg, sender):
        """Displays decrypted message, or extend circuit if needed"""
        if not self.circuit_setup:
            self.extend_circuit(msg)
        else:
            print(b"Client received: "+decrypt(decrypt(decrypt(msg, self.k_entry), self.k_middle), self.k_exit))

    def extend_circuit(self, msg):
        """
        Circuit extension protocol.
        Code is split into cases for key exchanges with entry, middle and exit relays respectively.
        """
        if self.k_entry is None:
            # No encryption in first diffie-hellman exchange
            self.k_entry = self.get_key(msg)
            if not self.k_entry:
                return
            self.generate_diff_hell_nums()

            # Extend circuit to middle relay
            extend_msg = compose_extend_msg(self.tor_relays[1], self.p, self.g, self.A)

            # TODO: Send the encrypted payload to extend the circuit
            encrypted_msg = encrypt(extend_msg, self.k_entry)
            self.send_payload(encrypted_msg, self.entry_relay)

        elif self.k_middle is None:
            # TODO: Decrypt the message
            decrypted_msg = decrypt(msg, self.k_entry)

            self.k_middle = self.get_key(decrypted_msg)
            if not self.k_entry:
                return
            self.generate_diff_hell_nums()

            # Extend circuit to exit relay
            extend_msg = compose_extend_msg(self.tor_relays[2], self.p, self.g, self.A)

            # TODO: Send the next payload to extend the circuit
            encrypted_msg = encrypt(encrypt(extend_msg, self.k_middle),self.k_entry)
            self.send_payload(encrypted_msg, self.entry_relay)

        elif self.k_exit is None:

            # TODO: Decrypt the message
            decrypted_msg = decrypt(decrypt(msg, self.k_entry), self.k_middle)

            self.k_exit = self.get_key(decrypted_msg)
            if not self.k_entry:
                return

            # No diffie-hellman is done here, message to connect the exit relay to the server
            extend_msg = compose_extend_msg(SERVER_ID, 0,0,0)

            # TODO: Send encrypted payload to connect the exit relay to the server
            encrypted_msg = encrypt(encrypt(encrypt(extend_msg, self.k_exit), self.k_middle), self.k_entry)
            self.send_payload(encrypted_msg, self.entry_relay)

            self.circuit_setup = True

    def send_to_server(self, msg):
        """Function called by end user to access the server once the TOR circuit is set-up"""
        if not self.circuit_setup:
            print("ERROR: TOR circuit not set up properly!")
        else:

            # TODO: Sends full onion payload to the guard relay
            onion_payload = encrypt(encrypt(encrypt(msg, self.k_exit), self.k_middle), self.k_entry)
            self.send_payload(onion_payload, self.entry_relay)

    def select_tor_relays(self):
        """Choose 3 relays from the directory authority"""
        self.tor_relays = authority.get_circuit_ids()

    def setup_tor_circuit(self):
        if self.circuit_setup:
            print("ERROR: TOR circuit already set up!")

        self.generate_diff_hell_nums()
        self.entry_relay = authority.find_relay(self.tor_relays[0])
        self.entry_relay.prev = self
        extend_msg = compose_extend_msg(self.tor_relays[0], self.p, self.g, self.A)

        # TODO: Start the circuit extension.
        self.send_payload(extend_msg, self.entry_relay)


authority = DirectoryAuthoritiy()
authority.maintain_consensus()
server = Server()
client = Client()
client.select_tor_relays()
client.setup_tor_circuit()
client.send_to_server(b"Hello Andi")
