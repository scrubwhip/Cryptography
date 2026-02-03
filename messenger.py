import os
import pickle
import string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Serialization helpers
def serializePK(pk):
    return pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def deserializePK(pk_bytes):
    return serialization.load_pem_public_key(pk_bytes)

# Double Ratchet helpers
"""Returns private/public key pair generated from curve P-256"""
def DHKeyGen() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

"""Uses a secret key and a public key to return a shared key via elliptic curve DH"""
def DH(sk: ec.EllipticCurvePrivateKey, pk: ec.EllipticCurvePublicKey) -> bytes:
        return sk.exchange(ec.ECDH(), pk)
        
"""Uses the current root key and some shared secret to derive the next root, send, and receive chain keys during ratchet. Implemented using a hash key derivation function -- DH Ratchet"""
def KDF_RK(RK: bytes, shared_secret: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = RK,
        info = bytes("Root Key", 'ascii')
    )

    rv = hkdf.derive(shared_secret)
    return rv[:32], rv[32:]
    
"""Uses a current chain key to derive the next chain key and a message key. Implemented using a hash MAC -- Symmetric Ratchet"""
def KDF_CK(CK: bytes) -> tuple[bytes, bytes]:
    h = hmac.HMAC(CK, hashes.SHA256())
    h.update(b"\x01")
    messageKey = h.finalize()

    h = hmac.HMAC(CK, hashes.SHA256())
    h.update(b"\x02")
    nextChainKey = h.finalize()
    return messageKey, nextChainKey
    
"""Uses AES-GCM to encrypt a sent message under a message key, uses a random nonce and authenticates the header"""
def ENC_AE(mk: bytes, message: bytes, header: bytes) -> bytes:
    aesScheme = AESGCM(mk)
    nonce = os.urandom(12)
    
    return nonce + aesScheme.encrypt(nonce, message, header)
    
"""Uses AES-GCM to decrypt a received message under the message key, extracts nonce from ciphertext and verifies the authenticity of the header"""
def DEC_AE(mk: bytes, ct: bytes, header: bytes) -> str:
    aesScheme = AESGCM(mk)
    nonce = ct[:12]
    try:
        return aesScheme.decrypt(nonce, ct[12:], header).decode('ascii')
    except:
        return None

"""Creates a header dict object containing the sender's public ket, the previous chain length, and the message number."""
def HEADER(pk: ec.EllipticCurvePublicKey, P_L: int, N: int) -> dict[str: ec.EllipticCurvePublicKeyWithSerialization, str: int, str: int]:
    header = {
        'PK' : serializePK(pk),
        'P_L' : P_L,
        'msgNum' : N
    }
    return header

"""Certificate helper class that defines object with name and public key"""
class Certificate:
    def __init__(self, name, pk):
        self.name = name
        self.pk = serializePK(pk)

    def serialize(self) -> bytes:
        return pickle.dumps(self)

"""State helper class that defines object with the necessary double ratchet attributes for each action"""
class State:
    def __init__(self):
        self.DH_S = None
        self.DH_R = None
        self.RK = None
        self.CK_S = None
        self.CK_R = None
        self.N_S = 0
        self.N_R = 0
        self.P_L = 0

    """Initializes state for Alice upon sending first message to Bob"""
    def ratchetInitAlice(self, shared_secret: bytes, b_pk: ec.EllipticCurvePublicKey) -> object:
        self.DH_S = DHKeyGen()
        self.DH_R = b_pk
        self.RK, self.CK_S = KDF_RK(shared_secret, DH(self.DH_S[0], self.DH_R))
        self.CK_R = None
        self.N_S = 0
        self.N_R = 0
        self.P_L = 0
        return self
    
    """Initializes state for Bob upon receiving first message from Alice"""
    def ratchetInitBob(self, shared_secret: bytes, pair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]) -> object:
        self.DH_S = pair
        self.DH_R = None
        self.RK = shared_secret
        self.CK_S = None
        self.CK_R = None
        self.N_S = 0
        self.N_R = 0
        self.P_L = 0
        return self
    

class MessengerServer:
    """Initializes server with a secret signing key and a secret decryption key"""
    def __init__(self, server_signing_key: ec.EllipticCurvePrivateKey, server_decryption_key: ec.EllipticCurvePrivateKey):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key
    
    """Uses an elliptic curve signing algorithm to sign a client's certificate"""
    def signCert(self, cert: Certificate) -> bytes:
        sig = self.server_signing_key.sign(
            cert.serialize(),
            ec.ECDSA(hashes.SHA256())
        )
        return sig

    """Uses a CCA version of ElGamal to decrypt a reported message from a client"""
    def decryptReport(self, ct_dict: dict[str: ec.EllipticCurvePublicKey, str: bytes, str: bytes]) -> str:
        nonce = ct_dict['NONCE']
        client_ephemeral_pk = ct_dict['EPHEMERAL PK']
        ct = ct_dict['CT']
        ephemeral_pk_bytes = serializePK(client_ephemeral_pk)

        shared_secret = self.server_decryption_key.exchange(ec.ECDH(), client_ephemeral_pk)
        
        h = hashes.Hash(hashes.SHA256())
        h.update(ephemeral_pk_bytes+shared_secret)

        shared_key = h.finalize()
        aesScheme = AESGCM(shared_key)

        return aesScheme.decrypt(nonce, ct, ephemeral_pk_bytes).decode('ascii')

class MessengerClient:
    """Initializes client with their name, the server's signature verification public key, the server's encryption public key for ElGamal, an initial Diffie Hellman key pair from curve P-256, an empty dictionary for the client's verified contacts, and an empty dictionary for the client's communication connections."""
    def __init__(self, name: str, server_signing_pk: ec.EllipticCurvePublicKey, server_encryption_pk: ec.EllipticCurvePublicKey):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.conns = {}
        self.certs = {}
    
    """Generates a certificate with the client's name and public key to be sent to the server for signing"""
    def generateCertificate(self) -> Certificate:
        return Certificate(self.name, self.public_key)

    """Verifies the authenticity of a certificate using the server's verification public key, adds certificate to verified contacts if successful"""
    def receiveCertificate(self, certificate: Certificate, signature: bytes) -> None:
        try:
            self.server_signing_pk.verify(
                signature,
                certificate.serialize(),
                ec.ECDSA(hashes.SHA256()),
            )
        except:
            raise ValueError("Invalid Signature")
        self.certs[certificate.name] = certificate
        return
    
    """Updates the current sending chain key and the current message key using chain key derivation. Increases sent message number and returns it along with the new message key."""
    def RatchetSendKey(self, state: State) -> tuple[int, bytes]:
        state.CK_S, mk = KDF_CK(state.CK_S)
        N_S = state.N_S+1
        return N_S, mk
    
    """Updates sent message number, extracts new message key. Creates a header with current sending public key, previous chain length, and number of messages sent"""
    def RatchetEnc(self, state: State, message: str) -> tuple[bytes, bytes]:
        state.N_S, mk = self.RatchetSendKey(state)
        header = HEADER(state.DH_S[1], state.P_L, state.N_S)
        return pickle.dumps(header), ENC_AE(mk, bytes(message, 'ascii'), pickle.dumps(header))
    
    """Checks if the DH receive key needs to be updated. If so, performs a ratchet on the keys. Regardless, derives new receiving chain key and message decryption key"""
    def RatchetReceiveKey(self, state: State, header: dict[str: ec.EllipticCurvePublicKeyWithSerialization, str: int, str: int]) -> bytes:
        if state.DH_R is None or serializePK(state.DH_R) != pickle.loads(header)['PK']:
            self.DHRatchet(state, header)
        state.CK_R, mk = KDF_CK(state.CK_R)
        state.N_R += 1
        return mk
    
    """Updates message decryption key, decrypts message"""
    def RatchetDec(self, state: State, ct: bytes, header: bytes) -> bytes: 
        mk = self.RatchetReceiveKey(state, header)
        if mk is None:
            return None
        return DEC_AE(mk, ct, header)
    
    """Performs a ratchet on the rook and DH keys. Updates sender's DH key using header, updates root chain key and receiving chain key, generates new DH keys, then updates root key and sending chain key"""
    def DHRatchet(self, state: State, header: bytes) -> None:
        state.P_L = state.N_S
        state.N_S = 0
        state.N_R = 0
        state.DH_R = deserializePK(pickle.loads(header)['PK'])
        state.RK, state.CK_R = KDF_RK(state.RK, DH(state.DH_S[0], state.DH_R))
        state.DH_S = DHKeyGen()
        state.RK, state.CK_S = KDF_RK(state.RK, DH(state.DH_S[0], state.DH_R))

    """If not previously connected, establishes a session between self and receiver. Sends encrypted message to receiver"""
    def sendMessage(self, name: str, message: str) -> bytes:
        if name not in self.conns:
            pk_bytes = self.certs[name].pk
            b_pk = deserializePK(pk_bytes)

            shared_secret = DH(self.private_key, b_pk)
            self.conns[name] = State().ratchetInitAlice(shared_secret, b_pk)
        
        state = self.conns[name]
        return self.RatchetEnc(state, message)

    """If not previously connected, establishes a session between self an sender. Decrypts encrypted message"""
    def receiveMessage(self, name: str, header: bytes, ct: bytes) -> str:
        if name not in self.conns:
            shared_secret = DH(self.private_key, deserializePK(self.certs[name].pk))
            self.conns[name] = State().ratchetInitBob(shared_secret, [self.private_key, self.public_key])
        state = self.conns[name]
        return self.RatchetDec(state, ct, header)
        
    """Uses a CCA ElGamal to encrypt a report. Returns plaintext and encryption of report for testing purposes"""
    def report(self, name: str, message: str) -> tuple[str, dict[str: ec.EllipticCurvePublicKey, str: bytes, str: bytes]]:
        ephemeral_client_sk, ephemeral_client_pk = DHKeyGen()

        shared_secret = ephemeral_client_sk.exchange(ec.ECDH(), self.server_encryption_pk)

        ephemeral_client_pk_bytes = serializePK(ephemeral_client_pk)

        h = hashes.Hash(hashes.SHA256())
        h.update(ephemeral_client_pk_bytes+shared_secret)
        shared_key = h.finalize()

        aesScheme = AESGCM(shared_key)
        nonce = os.urandom(12)

        ct_dict = {'EPHEMERAL PK': ephemeral_client_pk,
              'NONCE': nonce,
              'CT': aesScheme.encrypt(nonce, bytes(name+": "+message, 'ascii'), ephemeral_client_pk_bytes)
        }
        return name+": "+message, ct_dict
