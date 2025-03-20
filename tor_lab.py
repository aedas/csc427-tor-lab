from abc import ABC, abstractmethod
from cryptography.fernet import Fernet
import random
import base64
import os

EXTEND_PREFIX = b"EXTEND:" # EXTEND:id,p,g,A
EXTEND_REPLY_PREFIX = b"EXTRPY:" # EXTRPY:B


# https://codingfleet.com/transformation-details/implementing-diffie-hellman-key-exchange-algorithm-in-python/
def generate_prime_number():
    """
    Generate a random prime number between 100 and 1000.
    """
    prime = random.randint(100, 1000)
    while not is_prime(prime):
        prime = random.randint(100, 1000)
    #print(prime)
    return prime

def is_prime(n):
    """
    Check if a number is prime.
    """
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

# Payload of command to extend circuit with diffie-hellman parameters
def composeExtendMsg(id, p, g, A):
    return EXTEND_PREFIX + str.encode(str(id)+","+str(p)+","+str(g)+","+str(A))

# Payload for diffie hellman reply handshake
def composeExtendReplyMsg(B):
    return EXTEND_REPLY_PREFIX + str.encode(str(B))

def generateFernetKey(seed):
    rng = random.Random(seed)
    return base64.urlsafe_b64encode(bytes([rng.randint(0, 255) for i in range(32)]))

def encrypt(payload, key):
    return Fernet(generateFernetKey(key)).encrypt(payload)

def decrypt(payload, key):
    #print(key, payload)
    #print(payload[len(str(key).encode()):])
    return Fernet(generateFernetKey(key)).decrypt(payload)

def parseExtendMsg(msg):
    if not msg.startswith(EXTEND_PREFIX):
        print("ERROR: Cannot parse extend message!")
        return
    content = msg[len(EXTEND_PREFIX):].split(b",")
    return [int(x) for x in content]

def parseExtendReply(msg):
    #print(msg)
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
        if id == -1:
            return server
        #print(id)
        return [relay for relay in self.entry_relays + self.middle_relays + self.exit_relays if relay.id == id][0]

    def getCircuitIds(self):
        return [1,3,5]


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
        if msg.startswith(EXTEND_PREFIX) and sender == self.prev:
            content = parseExtendMsg(msg)
            if not content:
                return
            id, p, g, A = content
            b = generate_prime_number()
            B = (g**b) % p
            self.key = (A**b) % p
            #print("HI",composeExtendReplyMsg(B))
            self.send_payload(composeExtendReplyMsg(B), self.prev)
        elif sender == self.next:
            self.send_payload(encrypt(msg, self.key), self.prev)
        elif sender == self.prev:
            decrypted_msg = decrypt(msg, self.key)
            if self.next is None:
                #print("LIGMA", decrypted_msg, msg)
                content = parseExtendMsg(decrypted_msg)
                if not content:
                    return
                id, _, _, _= content
                self.next = da.findRelay(id)
                self.next.prev = self
            if self.next != server or not decrypted_msg.startswith(EXTEND_PREFIX):
                self.send_payload(decrypted_msg, self.next)

class Server(EncryptorDecryptor):
    def receive(self, msg, sender):
        print(b"SERVER received: "+msg)
        self.send_payload(b"LIGMA", sender)


class Client(EncryptorDecryptor):
    entry_relay = None
    k_entry = None
    k_middle = None
    k_exit = None
    circuit_setup = False

    # Placeholder
    tor_relays = []

    # Diffie-hellman key exchange
    a = 0
    p = 0

    def getKey(self, msg):
        content = parseExtendReply(msg)
        if not content:
            return
        B = content[0]
        ret = (B**self.a) % self.p
        self.p=generate_prime_number()
        self.a=generate_prime_number()
        return ret

    def receive(self, msg, sender):
        if self.k_entry is None:
            self.k_entry = self.getKey(msg)
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p
            self.send_payload(encrypt(composeExtendMsg(self.tor_relays[1], self.p, g, A), self.k_entry), self.entry_relay)
        elif self.k_middle is None:
            self.k_middle = self.getKey(decrypt(msg, self.k_entry))
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p
            self.send_payload(encrypt(
                encrypt(composeExtendMsg(self.tor_relays[2], self.p, g, A), self.k_middle),
            self.k_entry), self.entry_relay)
        elif self.k_exit is None:
            self.k_exit = self.getKey(decrypt(decrypt(msg, self.k_entry), self.k_middle))
            if not self.k_entry:
                return
            g=generate_prime_number()
            A=(g**self.a) % self.p
            self.send_payload(encrypt(encrypt(encrypt(composeExtendMsg(-1, self.p, g, A), self.k_exit), self.k_middle), self.k_entry), self.entry_relay)
            self.circuit_setup = True
        else:
            print(b"Client received: "+decrypt(decrypt(decrypt(msg, self.k_entry), self.k_middle), self.k_exit))

    def sendToServer(self, msg):
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
        self.send_payload(composeExtendMsg(self.tor_relays[0], self.p, g, A), self.entry_relay)


da = DirectoryAuthoritiy()
da.maintainConsensus()
server = Server()
client = Client()
client.selectTorRelays()
client.setupTorCircuit()
client.sendToServer(b"hello")