from dataclasses import dataclass
import secrets
import base64
from typing import List
import secp256k1
from binascii import unhexlify
from cffi import FFI
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from embit import bip39
from embit.bip32 import HDKey
from hashlib import sha256

from nostr.delegation import Delegation
from nostr.event import EncryptedDirectMessage, Event, EventKind
from . import bech32


class PublicKey:
    def __init__(self, raw_bytes: bytes) -> None:
        self.raw_bytes = raw_bytes

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_bytes, 8, 5)
        return bech32.bech32_encode("npub", converted_bits, bech32.Encoding.BECH32)

    def hex(self) -> str:
        return self.raw_bytes.hex()

    def verify_signed_message_hash(self, hash: str, sig: str) -> bool:
        pk = secp256k1.PublicKey(b"\x02" + self.raw_bytes, True)
        return pk.schnorr_verify(bytes.fromhex(hash), bytes.fromhex(sig), None, True)

    @classmethod
    def from_npub(cls, npub: str):
        """ Load a PublicKey from its bech32/npub form """
        hrp, data, spec = bech32.bech32_decode(npub)
        raw_public_key = bech32.convertbits(data, 5, 8)[:-1]
        return cls(bytes(raw_public_key))
    
    @classmethod
    def from_hex(cls, hex: str):
        return cls(unhexlify(hex))



class PrivateKey:
    def __init__(self, raw_secret: bytes = None) -> None:
        if raw_secret is not None:
            self.raw_secret = raw_secret
        else:
            self.raw_secret = secrets.token_bytes(32)

        sk = secp256k1.PrivateKey(self.raw_secret)
        self.public_key = PublicKey(sk.pubkey.serialize()[1:])
    

    @classmethod
    def from_nsec(cls, nsec: str):
        """ Load a PrivateKey from its bech32/nsec form """
        hrp, data, spec = bech32.bech32_decode(nsec)
        raw_secret = bech32.convertbits(data, 5, 8)[:-1]
        return cls(bytes(raw_secret))

    def bech32(self) -> str:
        converted_bits = bech32.convertbits(self.raw_secret, 8, 5)
        return bech32.bech32_encode("nsec", converted_bits, bech32.Encoding.BECH32)

    def hex(self) -> str:
        return self.raw_secret.hex()

    def tweak_add(self, scalar: bytes) -> bytes:
        sk = secp256k1.PrivateKey(self.raw_secret)
        return sk.tweak_add(scalar)

    def compute_shared_secret(self, public_key_hex: str) -> bytes:
        pk = secp256k1.PublicKey(bytes.fromhex("02" + public_key_hex), True)
        return pk.ecdh(self.raw_secret, hashfn=copy_x)

    def encrypt_message(self, message: str, public_key_hex: str) -> str:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.compute_shared_secret(public_key_hex)), modes.CBC(iv))

        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        return f"{base64.b64encode(encrypted_message).decode()}?iv={base64.b64encode(iv).decode()}"
    
    def encrypt_dm(self, dm: EncryptedDirectMessage) -> None:
        dm.content = self.encrypt_message(message=dm.cleartext_content, public_key_hex=dm.recipient_pubkey)

    def decrypt_message(self, encoded_message: str, public_key_hex: str) -> str:
        encoded_data = encoded_message.split('?iv=')
        encoded_content, encoded_iv = encoded_data[0], encoded_data[1]

        iv = base64.b64decode(encoded_iv)
        cipher = Cipher(algorithms.AES(self.compute_shared_secret(public_key_hex)), modes.CBC(iv))
        encrypted_content = base64.b64decode(encoded_content)

        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()

        return unpadded_data.decode()

    def sign_message_hash(self, hash: bytes) -> str:
        sk = secp256k1.PrivateKey(self.raw_secret)
        sig = sk.schnorr_sign(hash, None, raw=True)
        return sig.hex()

    def sign_event(self, event: Event) -> None:
        if event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE and event.content is None:
            self.encrypt_dm(event)
        if event.public_key is None:
            event.public_key = self.public_key.hex()
        event.signature = self.sign_message_hash(bytes.fromhex(event.id))

    def sign_delegation(self, delegation: Delegation) -> None:
        delegation.signature = self.sign_message_hash(sha256(delegation.delegation_token.encode()).digest())

    def __eq__(self, other):
        return self.raw_secret == other.raw_secret



@dataclass
class Bip39PrivateKey(PrivateKey):
    """
        Nostr PrivateKey that is derived from a BIP-39 mnemonic + optional BIP-39
        passphrase using the derivation path specified in NIP-06.
    """
    mnemonic: List[str] = None
    passphrase: str = None

    def __post_init__(self):
        if self.mnemonic is None:
            self.mnemonic = bip39.mnemonic_from_bytes(secrets.token_bytes(32)).split()
        
        if self.passphrase is None:
            # Per BIP-39 spec, no passphrase is the empty string
            self.passphrase = ""

        # Convert the mnemonic to the root HDKey and derive the Nostr key per NIP-06
        root = HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic=" ".join(self.mnemonic), password=self.passphrase))
        nostr_root = root.derive("m/44h/1237h/0h/0/0")

        super().__init__(raw_secret=nostr_root.secret)
    

    @classmethod
    def with_mnemonic_length(cls, num_words: int):
        """ Creates a new random BIP-39 mnemonic of the specified length to generate a new Nostr PK """
        if num_words == 24:
            # default is already 24 word-mnemonic
            return cls()
        elif num_words == 12:
            # 12-word mnemonic == 16-byte input entropy
            mnemonic = bip39.mnemonic_from_bytes(secrets.token_bytes(16)).split()
            return cls(mnemonic=mnemonic)
        else:
            raise Exception("Only mnemonics of length 12 or 24 are supported")



def mine_vanity_key(prefix: str = None, suffix: str = None) -> PrivateKey:
    if prefix is None and suffix is None:
        raise ValueError("Expected at least one of 'prefix' or 'suffix' arguments")

    while True:
        sk = PrivateKey()
        if prefix is not None and not sk.public_key.bech32()[5:5+len(prefix)] == prefix:
            continue
        if suffix is not None and not sk.public_key.bech32()[-len(suffix):] == suffix:
            continue
        break

    return sk


ffi = FFI()
@ffi.callback("int (unsigned char *, const unsigned char *, const unsigned char *, void *)")
def copy_x(output, x32, y32, data):
    ffi.memmove(output, x32, 32)
    return 1
