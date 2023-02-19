import pytest
import time

from nostr import bech32
from nostr.event import Event, EncryptedDirectMessage
from nostr.key import PrivateKey



class TestEvent:
    def test_event_default_time(self):
        """
            ensure created_at default value reflects the time at Event object instantiation
            see: https://github.com/jeffthibault/python-nostr/issues/23
        """
        event1 = Event(content='test event')
        time.sleep(1.5)
        event2 = Event(content='test event')
        assert event1.created_at < event2.created_at
    

    def test_content_only_instantiation(self):
        """ should be able to create an Event by only specifying content without kwarg """
        event = Event("Hello, world!")
        assert event.content is not None


    def test_event_id_recomputes(self):
        """ should recompute the Event.id to reflect the current Event attrs """
        event = Event(content="some event")

        # id should be computed on the fly
        event_id = event.id

        event.created_at += 10

        # Recomputed id should now be different
        assert event.id != event_id
    

    def test_note_id_bech32_conversion(self):
        """ should convert the event id to its `note`-prepended bech32 form """
        event = Event(content="some event")
        assert event.note_id.startswith("note")

        # reverse the bech32 encoding
        hrp, data, spec = bech32.bech32_decode(event.note_id)
        raw_event_id = bech32.convertbits(data, 5, 8)[:-1]

        # Should get the same event_id back
        assert event.id == bytes(raw_event_id).hex()
    

    def test_note_id_conformity(self):
        """ should produce the same note ID as a known published note """
        """
            A real-world note from fiatjaf:
            {
                "id": "deb8b23368b6c658c36cf16396927a045dee0b7707b4133d714fb67264cc10cc",
                "kind": 1,
                "pubkey": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
                "created_at": 1673361254,
                "content": "hello",
                "tags": [],
                "sig": "f5e5e8a477c6749ef8562c23cdfec7a6917c975ec55075489cb3319b8a2ccb78317335a6850fb3a3714777b1c22611419d6c81ce4b0b88db86e2d1662bb17540"
            }
        """
        event = Event(
            content="hello",
            public_key="3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            created_at=1673361254,
            kind=1,
            signature="f5e5e8a477c6749ef8562c23cdfec7a6917c975ec55075489cb3319b8a2ccb78317335a6850fb3a3714777b1c22611419d6c81ce4b0b88db86e2d1662bb17540"
        )
        assert event.id == "deb8b23368b6c658c36cf16396927a045dee0b7707b4133d714fb67264cc10cc"
        assert event.note_id == "note1m6utyvmgkmr93smv793edyn6q3w7uzmhq76px0t3f7m8yexvzrxqw46k83"


    def test_add_event_ref(self):
        """ should add an 'e' tag for each event_ref added """
        some_event_id = "some_event_id"
        event = Event(content="Adding an 'e' tag")
        event.add_event_ref(some_event_id)
        assert ['e', some_event_id] in event.tags


    def test_add_pubkey_ref(self):
        """ should add a 'p' tag for each pubkey_ref added """
        some_pubkey = "some_pubkey"
        event = Event(content="Adding a 'p' tag")
        event.add_pubkey_ref(some_pubkey)
        assert ['p', some_pubkey] in event.tags
    

    def test_extract_content_refs(self):
        """ should replace "@npub1" and "@note1" refs in `content` """
        pk1 = PrivateKey()
        pk2 = PrivateKey()
        e1 = Event("Hello, world!", public_key=pk2.public_key.hex())
        event = Event(
            f"Hello, @{pk1.public_key.bech32()}, did you see this: @{e1.note_id}?"
        )
        event.extract_content_refs()

        # The "@npub1" ref to pk1 should have been extracted into the first #[x] w/corresponding 'p' tag
        assert(f"@{pk1.public_key.bech32()}" not in event.content)
        assert("#[0]" in event.content)
        assert(event.tags[0][0] == 'p')
        assert(pk1.public_key.hex() == event.tags[0][1])

        # The "@note1" ref should have been extracted into the second #[x] w/corresponding 'e' tag
        assert(f"@{e1.note_id}" not in event.content)
        assert("#[1]" in event.content)
        assert(event.tags[1][0] == 'e')
        assert(e1.id == event.tags[1][1])

        # Torture test the regex
        event = Event(
            f"@@{pk1.public_key.bech32()}@{e1.note_id}foo@{pk2.public_key.bech32()}bar"
        )
        event.extract_content_refs()

        # The "@npub1" ref to pk1 should have been extracted into the first #[x] w/corresponding 'p' tag
        assert(f"@{pk1.public_key.bech32()}" not in event.content)
        assert("#[0]" in event.content)
        assert(event.tags[0][0] == 'p')
        assert(pk1.public_key.hex() == event.tags[0][1])

        # The "@note1" ref should have been extracted into the second #[x] w/corresponding 'e' tag
        assert(f"@{e1.note_id}" not in event.content)
        assert("#[1]" in event.content)
        assert(event.tags[1][0] == 'e')
        assert(e1.id == event.tags[1][1])

        # The "@npub1" ref to pk2 should have been extracted into the third #[x] w/corresponding 'p' tag
        assert(f"@{pk2.public_key.bech32()}" not in event.content)
        assert("#[2]" in event.content)
        assert(event.tags[2][0] == 'p')
        assert(pk2.public_key.hex() == event.tags[2][1])


class TestEncryptedDirectMessage:
    def setup_class(self):
        self.sender_pk = PrivateKey()
        self.sender_pubkey = self.sender_pk.public_key.hex()
        self.recipient_pk = PrivateKey()
        self.recipient_pubkey = self.recipient_pk.public_key.hex()


    def test_content_field_moved_to_cleartext_content(self):
        """ Should transfer `content` field data to `cleartext_content` """
        dm = EncryptedDirectMessage(content="My message!", recipient_pubkey=self.recipient_pubkey)
        assert dm.content is None
        assert dm.cleartext_content is not None
    

    def test_nokwarg_content_allowed(self):
        """ Should allow creating a new DM w/no `content` nor `cleartext_content` kwarg """
        dm = EncryptedDirectMessage("My message!", recipient_pubkey=self.recipient_pubkey)
        assert dm.cleartext_content is not None
    

    def test_recipient_p_tag(self):
        """ Should generate recipient 'p' tag """
        dm = EncryptedDirectMessage(cleartext_content="Secret message!", recipient_pubkey=self.recipient_pubkey)
        assert ['p', self.recipient_pubkey] in dm.tags
    

    def test_unencrypted_dm_has_undefined_id(self):
        """ Should raise Exception if `id` is requested before DM is encrypted """
        dm = EncryptedDirectMessage(cleartext_content="My message!", recipient_pubkey=self.recipient_pubkey)

        with pytest.raises(Exception) as e:
            dm.id
        assert "undefined" in str(e)

        # But once we encrypt it, we can request its id
        self.sender_pk.encrypt_dm(dm)
        assert dm.id is not None
