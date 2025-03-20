from abc import ABC, abstractmethod

EXTEND_PREFIX = "EXTEND:" # EXTEND:id,p,g,A
EXTEND_REPLY_PREFIX = "EXTRPY:" # EXTRPY:B


# Payload of command to extend circuit with diffie-hellman parameters
def composeExtendMsg(id, p, g, A):
    return EXTEND_PREFIX+str(id)+","+str(p)+","+str(g)+","+str(A)

# Payload for diffie hellman reply handshake
def composeExtendReplyMsg(B):
    return EXTEND_REPLY_PREFIX+str(B)

def encrypt(payload, key):
    return None

def decrypt(payload, key):
    return None



class DirectoryAuthoritiy:
    entry_relays = []
    middle_relays = []
    exit_relays = []
    def maintainConsensus(self):
        # Just reads a csv file and sets up network
        self.entry_relays = []
        self.middle_relays = []
        self.exit_relays = []
        pass
    def findRelay(self, id):

        # Directly connect to server (for exit relay)
        if id == -1:
            return server
        return (filter(lambda relay: relay.id == id, self.entry_relays)
            + filter(lambda relay: relay.id == id, self.middle_relays)
            + filter(lambda relay: relay.id == id, self.exit_relays))


class EncryptorDecryptor(ABC):
    @abstractmethod
    def receive(self, msg, sender):
        pass

    def send_payload(self, msg, target):
        target.receive(msg,self)

class Relay(EncryptorDecryptor):
    # prev: Previous relay, or client
    # next: Next relay, or server
    id = None
    prev = None
    next = None
    key = None
    def __init__(self, id):
        self.id = id
    def receive(self, msg, sender):
        if msg.startsWith(EXTEND_PREFIX) and sender == self.prev:
            b = 0
            # B = g^b mod p
            self.key = 0 # A^b mod p
            B = b
            self.send_payload(composeExtendReplyMsg(B), self.prev)
        elif sender == self.next:
            self.send_payload(encrypt(msg, self.key), self.prev)
        elif sender == self.prev:
            decrypted_msg = decrypt(msg, self.key)
            if self.next is None:
                self.next = da.findRelay(None)
                self.next.prev = self
            if self.next != server or not decrypted_msg.startsWith(EXTEND_PREFIX):
                self.send_payload(decrypted_msg, self.next)

class Server(EncryptorDecryptor):
    def receive(self, msg, sender):
        print("SERVER received: "+msg)
        self.send_payload("LIGMA", sender)


class Client(EncryptorDecryptor):
    entry_relay = None
    k_entry = None
    k_middle = None
    k_exit = None
    circuit_setup = False

    # Placeholder
    tor_relays = [0,1,2]

    # Diffie-hellman key exchange
    a = 0
    p = 0

    def receive(self, msg, sender):
        if self.k_entry is None:
            self.k_entry = 0 # B^a mod p
            self.p=0
            g=0
            self.a=0
            A=0
            self.send_payload(encrypt(composeExtendMsg(self.tor_relays[1], self.p, g, A), self.k_entry), self.entry_relay)
        elif self.k_middle is None:
            self.k_middle = 0 # B^a mod p
            self.p=0
            g=0
            self.a=0
            A=0
            self.send_payload(encrypt(
                encrypt(composeExtendMsg(self.tor_relays[2], self.p, g, A), self.k_middle),
            self.k_entry), self.entry_relay)
        elif self.k_exit is None:
            self.k_exit = 0 # B^a mod p
            self.circuit_setup = True
            self.p=0
            g=0
            self.a=0
            A=0
            self.send_payload(encrypt(encrypt(encrypt(composeExtendMsg(-1, self.p, g, A), self.k_exit), self.k_middle), self.k_entry), self.entry_relay)
        else:
            print("Client received: "+decrypt(decrypt(decrypt(msg, self.k_entry), self.k_middle), self.k_exit))

    def send(self, msg):
        if not self.circuit_setup:
            print("ERROR: TOR circuit not set up properly!")
        else:
            self.send_payload(encrypt(encrypt(encrypt(msg, self.k_exit), self.k_middle), self.k_entry), self.entry_relay)

    def selectTorRelays(self):
        self.tor_relays = [0,0,0]

    def setupTorCircuit(self):
        if self.circuit_setup:
            print("ERROR: TOR circuit already set up!")
        self.p=0
        g=0
        self.a=0
        A=0
        self.entry_relay = da.findRelay(self.tor_relays[0])
        self.entry_relay.prev = self
        self.send_payload(composeExtendMsg(self.tor_relays[0], self.p, g, A))
        pass


da = DirectoryAuthoritiy()
server = Server()