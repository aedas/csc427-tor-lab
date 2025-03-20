from abc import ABC, abstractmethod
from tor_encrypt import *

EXTEND_PREFIX = b"EXTEND:" # EXTEND:id,p,g,A
EXTEND_REPLY_PREFIX = b"EXTRPY:" # EXTRPY:B
SERVER_ID = -1
CLIENT_ID = 0

# Payload of command to extend circuit with diffie-hellman parameters
def composeExtendMsg(id, p, g, A):
    return EXTEND_PREFIX + str.encode(str(id)+","+str(p)+","+str(g)+","+str(A))

# Payload for diffie hellman reply handshake
def composeExtendReplyMsg(B):
    return EXTEND_REPLY_PREFIX + str.encode(str(B))


def parseExtendMsg(msg):
    if not msg.startswith(EXTEND_PREFIX):
        print("ERROR: Cannot parse extend message!")
        return
    content = msg[len(EXTEND_PREFIX):].split(b",")
    return [int(x) for x in content]

def parseExtendReply(msg):
    if not msg.startswith(EXTEND_REPLY_PREFIX):
        print("ERROR: Cannot parse extend reply message!")
        return
    content = msg[len(EXTEND_REPLY_PREFIX):].split(b",")
    return [int(x) for x in content]


class DirectoryAuthoritiy:
    entry_relays = []
    middle_relays = []
    exit_relays = []
    def maintainConsensus(self):
        # Just reads a csv file and sets up network
        self.entry_relays = [Relay(1), Relay(2)]
        self.middle_relays = [Relay(3), Relay(4)]
        self.exit_relays = [Relay(5), Relay(6)]
        pass

    def findRelay(self, id):
        # Directly connect to server (for exit relay)
        if id == SERVER_ID:
            return server
        return [relay for relay in self.entry_relays + self.middle_relays + self.exit_relays if relay.id == id][0]

    def getCircuitIds(self):
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
    def __init__(self, id):
        self.id = id
    def receive(self, msg, sender):
        if msg.startswith(EXTEND_PREFIX) and sender == self.prev:
            content = parseExtendMsg(msg)
            if not content:
                return
            id, p, g, A = content
            b = generate_prime_number()
            B = (g**b) % p
            self.key = (A**b) % p
            reply_msg = composeExtendReplyMsg(B)
            # TODO: Send diffie-hellman reply message to previous hop
            self.send_payload(reply_msg, self.prev)
        elif sender == self.next:
            # TODO: Encrypt a layer and send it to previous hop
            self.send_payload(encrypt(msg, self.key), self.prev)
        elif sender == self.prev:
            decrypted_msg = decrypt(msg, self.key)
            # Or decrypted_msg.startswith(EXTEND_PREFIX)
            # Case for circuit extension
            if self.next is None:
                content = parseExtendMsg(decrypted_msg)
                if not content:
                    return
                id, _, _, _= content
                # TODO: Connect to next relay/hop
                self.next = da.findRelay(id)
                self.next.prev = self
            if self.next != server or not decrypted_msg.startswith(EXTEND_PREFIX):
                # TODO: Send decrypted message to next hop
                self.send_payload(decrypted_msg, self.next)

class Server(EncryptorDecryptor):
    """
    Simple server that sends a single response
    """
    id = SERVER_ID
    def receive(self, msg, sender):
        print(b"SERVER received: "+msg)
        self.send_payload(b"Welcome to CSC427", sender)


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

    def getKey(self, msg):
        """
        Gets shared secret from Server's public key message
        """
        content = parseExtendReply(msg)
        if not content:
            return
        B = content[0]
        ret = (B**self.a) % self.p

        # Different set of prime numbers for future diffie-hellman key exchanges
        self.p=generate_prime_number()
        self.a=generate_prime_number()
        return ret

    def receive(self, msg, sender):
        """
        Displays decrypted message, or extend circuit if needed
        """
        if not self.circuit_setup:
            self.extend_circuit(msg)
        else:
            print(b"Client received: "+decrypt(decrypt(decrypt(msg, self.k_entry), self.k_middle), self.k_exit))

    def extend_circuit(self, msg):
        """
        Circuit extension protocol. Code is split into cases for key exchanges with entry, middle and exit relays respectively.
        """
        if self.k_entry is None:
            self.k_entry = self.getKey(msg)
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p

            extend_msg = composeExtendMsg(self.tor_relays[1], self.p, g, A)
            # TODO: Send the next payload to extend the circuit
            self.send_payload(encrypt(extend_msg, self.k_entry), self.entry_relay)
        elif self.k_middle is None:
            self.k_middle = self.getKey(decrypt(msg, self.k_entry))
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p
            extend_msg = composeExtendMsg(self.tor_relays[2], self.p, g, A)
            # TODO: Send the next payload to extend the circuit
            self.send_payload(encrypt(encrypt(extend_msg, self.k_middle),self.k_entry), self.entry_relay)
        elif self.k_exit is None:
            self.k_exit = self.getKey(decrypt(decrypt(msg, self.k_entry), self.k_middle))
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p

            extend_msg = composeExtendMsg(SERVER_ID, 0,0,0)
            # TODO: Send the next payload to connect the exit relay to the server
            self.send_payload(encrypt(encrypt(encrypt(extend_msg, self.k_exit), self.k_middle), self.k_entry), self.entry_relay)
            self.circuit_setup = True

    def sendToServer(self, msg):
        """Function called by end user to access the server once the TOR circuit is set-up"""
        if not self.circuit_setup:
            print("ERROR: TOR circuit not set up properly!")
        else:
            self.send_payload(encrypt(encrypt(encrypt(msg, self.k_exit), self.k_middle), self.k_entry), self.entry_relay)

    def selectTorRelays(self):
        self.tor_relays = da.getCircuitIds()

    def setupTorCircuit(self):
        if self.circuit_setup:
            print("ERROR: TOR circuit already set up!")
        self.p=generate_prime_number()
        g=generate_prime_number()
        self.a=generate_prime_number()
        A=(g**self.a) % self.p
        self.entry_relay = da.findRelay(self.tor_relays[0])
        self.entry_relay.prev = self
        # TODO: Start the circuit extension.
        self.send_payload(composeExtendMsg(self.tor_relays[0], self.p, g, A), self.entry_relay)


da = DirectoryAuthoritiy()
da.maintainConsensus()
server = Server()
client = Client()
client.selectTorRelays()
client.setupTorCircuit()
client.sendToServer(b"Hello Andi")
client.sendToServer(input("Type anything to server: ").encode())