import time
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import List
from secp256k1 import PrivateKey, PublicKey
from hashlib import sha256

from nostr.message_type import ClientMessageType



class EventKind(IntEnum):
    SET_METADATA = 0
    TEXT_NOTE = 1
    RECOMMEND_RELAY = 2
    CONTACTS = 3
    ENCRYPTED_DIRECT_MESSAGE = 4
    DELETE = 5



@dataclass
class Event:
    public_key: str = None
    content: str = None
    created_at: int = None
    kind: int = EventKind.TEXT_NOTE
    tags: List[List[str]] = None
    id: str = None
    signature: str = None


    def __post_init__(self):
        if self.content is not None and not isinstance(self.content, str):
            # DMs initialize content to None but all other kinds should pass in a str
            raise TypeError("Argument 'content' must be of type str")

        if self.created_at is None:
            self.created_at = int(time.time())

        # Can't initialize the nested type above w/out more complex factory, so doing it here
        if self.tags is None:
            self.tags = []

        if self.id is None:
            self.compute_id()


    @classmethod
    def from_json(cls, event_json: str):
        """
            With or without the "event" outer level:
            {
                "event": {
                    "id": <event_id>,
                    "pubkey": <public_key>,
                    "created_at": 1674849977,
                    "kind": 1,
                    "tags": [],
                    "content": "Hello!",
                    "sig": ""
                }
            }
        """
        data = json.loads(event_json)
        if "event" in data:
            data = data["event"]
        return cls(
            public_key=data.get("pubkey"),
            content=data.get("content"),
            created_at=data.get("created_at"),
            kind=data.get("kind"),
            tags=data.get("tags"),
            id=data.get("id"),
            signature=data.get("sig"),
        )



    def serialize(self) -> bytes:
        data = [0, self.public_key, self.created_at, self.kind, self.tags, self.content]
        data_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        return data_str.encode()
    

    @property
    def pubkey_refs(self) -> List[str]:
        return [tag[1] for tag in self.tags if tag[0] == 'p']


    @property
    def event_refs(self) -> List[str]:
        return [tag[1] for tag in self.tags if tag[0] == 'e']


    def compute_id(self):
        self.id = sha256(self.serialize()).hexdigest()


    def add_pubkey_ref(self, pubkey:str):
        """ Adds a reference to a pubkey as a 'p' tag """
        self.tags.append(['p', pubkey])
        self.compute_id()


    def add_event_ref(self, event_id:str):
        """ Adds a reference to an event_id as an 'e' tag """
        self.tags.append(['e', event_id])
        self.compute_id()


    def verify(self) -> bool:
        pub_key = PublicKey(bytes.fromhex("02" + self.public_key), True) # add 02 for schnorr (bip340)

        # Always recompute id just in case something changed
        self.compute_id()

        return pub_key.schnorr_verify(bytes.fromhex(self.id), bytes.fromhex(self.signature), None, raw=True)


    def to_message(self) -> str:
        return json.dumps(
            [
                ClientMessageType.EVENT,
                {
                    "id": self.id,
                    "pubkey": self.public_key,
                    "created_at": self.created_at,
                    "kind": self.kind,
                    "tags": self.tags,
                    "content": self.content,
                    "sig": self.signature
                }
            ]
        )



@dataclass
class EncryptedDirectMessage(Event):
    recipient_pubkey: str = None
    cleartext_content: str = None
    reference_event_id: str = None


    def __post_init__(self):
        if self.content is not None:
            raise Exception("Encrypted DMs cannot use the `content` field; use `cleartext_content` instead.")

        if self.recipient_pubkey is None:
            raise Exception("Must specify a recipient_pubkey.")

        self.kind = EventKind.ENCRYPTED_DIRECT_MESSAGE
        super().__post_init__()

        # Must specify the DM recipient's pubkey in a 'p' tag
        self.add_pubkey_ref(self.recipient_pubkey)

        # Optionally specify a reference event (DM) this is a reply to
        if self.reference_event_id:
            self.add_event_ref(self.reference_event_id)
