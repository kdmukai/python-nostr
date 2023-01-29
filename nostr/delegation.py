import time
from dataclasses import dataclass
from typing import List



@dataclass
class Delegation:
    delegator_pubkey: str
    delegatee_pubkey: str
    event_kinds: List[int]
    valid_from: int = None
    valid_until: int = None
    signature: str = None  # set in PrivateKey.sign_delegation

    @classmethod
    def from_token(cls, delegator_pubkey: str, delegation_token: str):
        # "nostr:delegation:<delegatee pubkey hex>:<condition&condition&condition>"
        parts = delegation_token.split(":")
        kinds = []
        valid_from = None
        valid_until = None
        for condition in parts[3].split("&"):
            if condition.startswith("kind"):
                kinds.append(int(condition.split("=")[1]))
            elif condition.startswith("created_at>"):
                valid_from = int(condition.split(">")[1])
            elif condition.startswith("created_at<"):
                valid_until = int(condition.split("<")[1])
        return cls(
            delegator_pubkey=delegator_pubkey,
            delegatee_pubkey=parts[2],
            event_kinds=kinds,
            valid_from=valid_from,
            valid_until=valid_until,
        )

    @property
    def conditions(self) -> str:
        conditions = [f"kind={kind}" for kind in self.event_kinds]
        if self.valid_from:
            conditions.append(f"created_at>{self.valid_from}")
        if self.valid_until:
            conditions.append(f"created_at<{self.valid_until}")
        return "&".join(conditions)
    
    @property
    def delegation_token(self) -> str:
        return f"nostr:delegation:{self.delegatee_pubkey}:{self.conditions}"

    def get_tag(self) -> list[str]:
        """ Called by Event """
        return [
            "delegation",
            self.delegator_pubkey,
            self.conditions,
            self.signature,
        ]


    def verify(self) -> bool:
        from binascii import hexlify
        from hashlib import sha256
        from nostr.key import PublicKey

        delegator = PublicKey.from_hex(self.delegator_pubkey)
        message_hash = hexlify(sha256(self.delegation_token.encode()).digest())
        return delegator.verify_signed_message_hash(hash=message_hash.decode(), sig=self.signature)
