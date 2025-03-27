
import random
from fernet import Fernet
import random
import base64


"""
Fernet Key encryption that uses Diffie-hellman keys as seed for simplicity.

References:
- Prime Generation: https://codingfleet.com/transformation-details/implementing-diffie-hellman-key-exchange-algorithm-in-python/
- Creation of user-defined fernet key: https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet
- Seeding to mimic os.urandom: https://stackoverflow.com/questions/37356338/is-there-a-predictable-replacement-for-os-urandom-using-pythons-random-module
"""
def generate_prime_number():

    prime = random.randint(100, 1000)
    while not is_prime(prime):
        prime = random.randint(100, 1000)
    return prime

def is_prime(n):

    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_fernet_key(seed):
    rng = random.Random(seed)
    return base64.urlsafe_b64encode(bytes([rng.randint(0, 255) for i in range(32)]))

def encrypt(payload, key):
    """
    Encrypts using diffie-hellman key as seed
    """
    ret = Fernet(generate_fernet_key(key)).encrypt(payload)
    # print(b"Encrypt "+payload[:20]+b"... with key="+str(key).encode()+b" => "+ret[:20]+b"...")
    return ret

def decrypt(payload, key):
    """
    Decrypts using diffie-hellman key as seed
    """
    ret = Fernet(generate_fernet_key(key)).decrypt(payload)
    # print(b"Decrypt "+payload[:20]+b"... with key="+str(key).encode()+b" => "+ret[:20]+b"...")
    return ret