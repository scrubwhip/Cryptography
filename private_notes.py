import pickle
import os
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PrivNotes:
  MAX_NOTE_LEN = 2048
  
  """Helper methods"""

  def getnonce(self, counter):
    """Return the HMAC of the current counter to be used as a nonce"""
    return self.getmac(counter.to_bytes(8, 'big'))[:12]
  
  def getmac(self, message):
    """Return a hash-based message authentication code of the provided message"""
    h = hmac.HMAC(self.mackey, hashes.SHA256(), backend=None)
    h.update(message)
    return h.finalize()
  
  def gethash(self, data):
    """Return the SHA256 hash of the provided data. Used for checksum and mackey derivation"""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()
  
  def pad(self, note):
    """Expects: ascii string note
    Returns: padded byte string note"""

    """Pad the right of the note with null bytes to make note divisible into blocks"""
    blocksizenote = note + (16-len(note)%16) * "\x00"

    """Create padding block of byte representation of note length"""
    paddingblock = len(note).to_bytes(16, 'big')

    """Calculate number of blocks needed to get to max note length + one block"""
    numblocks = (self.MAX_NOTE_LEN-len(blocksizenote))//16 + 1

    """Padding is padding block repeated (numblocks) times"""
    padding = numblocks * paddingblock
    
    """Return padded byte string"""
    return bytes(blocksizenote, 'ascii')+padding
  
  def unpad(self, paddednote):
    """Expects: bytestring paddednote
    Returns: unpadded bytestring"""

    """Extract note length from last block of decrypted plaintext"""
    length = int.from_bytes(paddednote[-16:], 'big')

    """Return the plaintext up to that length"""
    return paddednote[:length]

  """Functional methods"""

  def __init__(self, password, data = None, checksum = None):
    """Initialize empty key-value store"""
    self.kvs = {}

    """If checksum or data is provided but not both, raise incorrect checksum error"""
    if data is None and checksum is not None or data is not None and checksum is None:
      raise ValueError('Incorrect Parameters')

    """If data is already provided, attempt to unpickle the data. If data is in malformed serialized format, raise value error. If successful, load deserialized data into the key value store and extract salt"""
    """If no data is provided, generate random salt and add it to the key value store"""
    if data is not None:
      try:
        pickle.loads(bytes.fromhex(data))
      except:
        raise ValueError('Malformed serialized format')
      self.kvs = pickle.loads(bytes.fromhex(data))
      self.mysalt = self.kvs["salt"]

      """Check data/checksum match: if data and checksum are provided, find the SHA256 hash of the provided serialized data. If the hash of the provided data doesn't match the checksum, raise incorrect checksum error"""
      if checksum is not None:
        checkval = self.gethash(bytes.fromhex(data)).hex()
        if checkval != checksum:
          raise ValueError('Incorrect Checksum')
    else:
      self.mysalt = os.urandom(16)
      self.kvs["salt"] = self.mysalt
    
    """Initialize counter item as 0. We will use the HMAC of this counter for the nonce of each note"""
    if "Counter" not in self.kvs:
      self.kvs["Counter"] = 0

    """Use salt and SHA256 to define key derivation function"""
    kdf = PBKDF2HMAC(
      algorithm = hashes.SHA256(),
      length = 32,
      salt = self.mysalt,
      iterations = 2000000
    )

    """Use key derivation function to derive key from password"""
    self.key = kdf.derive(bytes(password, 'ascii'))

    """Use a hash of the key to derive an HMAC key"""
    self.mackey = self.gethash(self.key)

    """Define AESGCM encryption scheme using key derived from password"""
    self.aescheme = AESGCM(self.key)

    """Check password: for each tag-ciphernote pair other than the salt and counter, attempt to decrypt the ciphernote using AESGCM with key derived from provided password. If an exception occurs during decryption, the key and therefore the password are incorrect, or the data was tampered with."""
    for tag, ciphernote in self.kvs.items():
      if tag in ["salt", "Counter"]:
        continue
      try:
        nonce = ciphernote[:12]
        self.aescheme.decrypt(nonce, ciphernote[12:], tag)
      except:
        raise ValueError('Incorrect password or corrupted data')

  def dump(self):
    """Create an HMAC instance to authenticate the byte string of the serialized data using the key and update the checksum"""
    checksum = self.gethash(pickle.dumps(self.kvs)).hex()

    """Return serialized key-value store in hex format"""
    return pickle.dumps(self.kvs).hex(), checksum

  def get(self, title):
    """Find the HMAC of the associated title"""
    tag = self.getmac(bytes(title, 'ascii'))

    """If tag is already present as a title in the key-value store, decrypt the note associated with the tag using AESGCM and first 12 bytes of the note as the nonce. Return decrypted note as an ascii decoded string."""
    if tag in self.kvs:
      nonce = self.kvs[tag][:12]
      paddednote = self.aescheme.decrypt(nonce, self.kvs[tag][12:], tag)
      return self.unpad(paddednote).decode('ascii')
    
    """If tag is not present, return None"""
    return None

  def set(self, title, note):
    """If note length exceeds maximum length, raise value error"""
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    """Create tag from title"""
    tag = self.getmac(bytes(title, 'ascii'))

    """Generate 12 byte nonce derived from the HMAC of the counter; update counter"""
    nonce = self.getnonce(self.kvs["Counter"])
    self.kvs["Counter"] = self.kvs["Counter"]+1

    """Encrypt note using AESGCM scheme with key, nonce, and tag associated with title"""
    ciphernote = nonce + self.aescheme.encrypt(nonce, self.pad(note), tag)

    """If tag is already present as a title in the key-value store, replace existing note with new note and warn user"""
    if tag in self.kvs:
      print("Warning: Overwriting existing note")
      self.kvs[tag] = ciphernote
      return
    
    """If tag is not present, add tag and note to key-value store"""
    self.kvs[tag] = ciphernote
    
  def remove(self, title):
    """Create new HMAC instance to authenticate the title using the key"""
    tag = self.getmac(bytes(title, 'ascii'))

    """If the authenticated tag is in the key-value store, delete the associated entry and return True"""
    if tag in self.kvs:
      del self.kvs[tag]
      return True
    return False
