import time
import json
import re
from binascii import unhexlify, hexlify
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List
from secp256k1 import PublicKey
from hashlib import sha256

from . import bech32
from .message_type import ClientMessageType



class EventKind:
    SET_METADATA = 0
    TEXT_NOTE = 1
    RECOMMEND_RELAY = 2
    CONTACTS = 3
    ENCRYPTED_DIRECT_MESSAGE = 4
    DELETE = 5
    REACTIONS = 7
    LIST = 3000


    ALL_KINDS = {
        SET_METADATA: "Set Metadata",
        TEXT_NOTE: "Text note",
        RECOMMEND_RELAY: "Recommend relay",
        CONTACTS: "Contacts",
        ENCRYPTED_DIRECT_MESSAGE: "Encrypted DMs",
        DELETE: "Delete",
        REACTIONS: "Reactions",
        LIST: "Lists",
    }



@dataclass
class Event:
    content: str = None
    public_key: str = None
    created_at: int = None
    kind: int = EventKind.TEXT_NOTE
    tags: List[List[str]] = field(default_factory=list)  # Dataclasses require special handling when the default value is a mutable type
    signature: str = None


    def __post_init__(self):
        if self.content is not None and not isinstance(self.content, str):
            # DMs initialize content to None but all other kinds should pass in a str
            raise TypeError("Argument 'content' must be of type str")

        if self.created_at is None:
            self.created_at = int(time.time())
        
        self.finalized_event_id = None


    @classmethod
    def from_dict(cls, event_dict: dict):
        return cls(
            public_key=event_dict.get("pubkey"),
            content=event_dict.get("content"),
            created_at=event_dict.get("created_at"),
            kind=event_dict.get("kind"),
            tags=event_dict.get("tags"),
            signature=event_dict.get("sig"),
        )

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
        return Event.from_dict(data)

    @classmethod
    def bech32_to_hex(cls, note_id):
        hrp, data, spec = bech32.bech32_decode(note_id)
        raw_hex = bech32.convertbits(data, 5, 8)[:-1]
        return hexlify(bytes(raw_hex))


    @staticmethod
    def serialize(public_key: str, created_at: int, kind: int, tags: List[List[str]], content: str) -> bytes:
        data = [0, public_key, created_at, kind, tags, content]
        data_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        return data_str.encode()


    @staticmethod
    def compute_id(public_key: str, created_at: int, kind: int, tags: List[List[str]], content: str):
        return sha256(Event.serialize(public_key, created_at, kind, tags, content)).hexdigest()


    @property
    def id(self) -> str:
        # Always recompute the id to reflect the up-to-date state of the Event
        current_id = Event.compute_id(self.public_key, self.created_at, self.kind, self.tags, self.content)
        if self.finalized_event_id is not None and self.finalized_event_id != current_id:
            raise Exception("Finalized Event was edited!")
        return current_id


    @property
    def note_id(self) -> str:
        converted_bits = bech32.convertbits(bytes.fromhex(self.id), 8, 5)
        return bech32.bech32_encode("note", converted_bits, bech32.Encoding.BECH32)


    @property
    def pubkey_refs(self) -> List[str]:
        return [tag[1] for tag in self.tags if tag[0] == 'p']


    @property
    def event_refs(self) -> List[str]:
        return [tag[1] for tag in self.tags if tag[0] == 'e']
    

    def finalize(self) -> str:
        """ Lock the Event and prevent and further changes """
        if self.finalized_event_id is not None:
            raise Exception("Event was already finalized!")

        # Alter the content as needed and replace with refs
        self.extract_content_refs()

        # Store finalized result
        self.finalized_event_id = self.id
        return self.finalized_event_id


    def extract_content_refs(self):
        """
            Looks for "@npub1..." or "@note1..." in the `Event.content` and converts to
            "#[n]" syntax w/associated 'p' and 'e' tags.
        """
        from nostr import key

        at_ref_options = ["npub1", "note1"]
        re_patterns = [f"@{op}[{bech32.CHARSET}]{{58}}" for op in at_ref_options]
        regex = re.compile(f"""({ "|".join(re_patterns) })""")

        ref_matches: List[str] = []
        for ref_index in [m.start() for m in regex.finditer(self.content)]:
            for option in at_ref_options:
                # Remember to skip the "@" that precedes the reference
                if self.content[ref_index+1:].startswith(option):
                    ref_matches.append(self.content[ref_index+1:ref_index+1 + len(option) + 58])
        
        for i, match in enumerate(ref_matches):
            if match.startswith("npub1"):
                # Convert npub to pubkey hex
                self.add_pubkey_ref(key.PublicKey.from_npub(match).hex())
            elif match.startswith("note1"):
                self.add_event_ref(Event.bech32_to_hex(match))

            self.content = self.content.replace("@" + match, f"#[{len(self.tags) - 1}]")


    def add_pubkey_ref(self, pubkey:str):
        """ Adds a reference to a pubkey as a 'p' tag """
        if self.finalized_event_id is not None:
            raise Exception("Cannot edit a finalized Event!")
        self.tags.append(['p', pubkey])


    def add_event_ref(self, event_id:str):
        """ Adds a reference to an event_id as an 'e' tag """
        if self.finalized_event_id is not None:
            raise Exception("Cannot edit a finalized Event!")
        self.tags.append(['e', event_id])


    def verify(self) -> bool:
        pub_key = PublicKey(bytes.fromhex("02" + self.public_key), True)  # add 02 for schnorr (bip340)
        return pub_key.schnorr_verify(bytes.fromhex(self.id), bytes.fromhex(self.signature), None, raw=True)


    def to_json(self) -> dict:
        return {
            "id": self.id,
            "pubkey": self.public_key,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.signature
        }
        

    def to_message(self) -> str:
        return json.dumps(
            [
                ClientMessageType.EVENT,
                self.to_json(),
            ]
        )



@dataclass
class EncryptedDirectMessage(Event):
    recipient_pubkey: str = None
    cleartext_content: str = None
    reference_event_id: str = None


    def __post_init__(self):
        if self.content is not None:
            self.cleartext_content = self.content
            self.content = None

        if self.recipient_pubkey is None:
            raise Exception("Must specify a recipient_pubkey.")

        self.kind = EventKind.ENCRYPTED_DIRECT_MESSAGE
        super().__post_init__()

        # Must specify the DM recipient's pubkey in a 'p' tag
        self.add_pubkey_ref(self.recipient_pubkey)

        # Optionally specify a reference event (DM) this is a reply to
        if self.reference_event_id is not None:
            self.add_event_ref(self.reference_event_id)


    @property
    def id(self) -> str:
        if self.content is None:
            raise Exception("EncryptedDirectMessage `id` is undefined until its message is encrypted and stored in the `content` field")
        return super().id
