import pytest
import time
from nostr.key import PrivateKey
from nostr.event import EventKind, Event, EncryptedDirectMessage



@pytest.fixture
def sender() -> PrivateKey:
    yield PrivateKey()

@pytest.fixture
def recipient() -> PrivateKey:
    yield PrivateKey()



def test_event_default_time():
    """
        ensure created_at default value reflects the time at Event object instantiation
        see: https://github.com/jeffthibault/python-nostr/issues/23
    """
    public_key = PrivateKey().public_key.hex()
    event1 = Event(public_key=public_key, content='test event')
    time.sleep(1.5)
    event2 = Event(public_key=public_key, content='test event')
    assert event1.created_at < event2.created_at



class TestEncryptedDirectMessage:    
    def test_create_dm(self, sender: PrivateKey, recipient: PrivateKey):
        """ should construct a publishable DM Event """
        dm = EncryptedDirectMessage(
            public_key=sender.public_key.hex(),
            cleartext_content="Secret message!",
            recipient_pubkey=recipient.public_key.hex(),
        )

        assert dm.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE

        # DM Events must have a 'p' tag for the recipient
        has_p_tag = False
        for tag in dm.tags:
            if tag[0] == 'p' and tag[1] == recipient.public_key.hex():
                has_p_tag = True
                break
        assert has_p_tag

        # Event has no content until the Event is signed
        assert dm.content is None

        sender.sign_event(dm)
        assert dm.content is not None

        # Event signature should be valid for the Event.id
        assert dm.verify()


    def test_dm_encryption(self, sender: PrivateKey, recipient: PrivateKey):
        """ should encrypt the DM's cleartext message and be decryptable by the recipient """
        cleartext_content = "This is my secret message!"

        dm = EncryptedDirectMessage(
            public_key=sender.public_key.hex(),
            cleartext_content=cleartext_content,
            recipient_pubkey=recipient.public_key.hex(),
        )

        sender.sign_event(dm)

        assert dm.content is not None
        assert dm.content != cleartext_content

        # Recipient's PK should be able to decrypt the content
        decrypted_msg = recipient.decrypt_message(encoded_message=dm.content, public_key_hex=sender.public_key.hex())
        assert decrypted_msg == cleartext_content


    def test_dm_content_not_allowed(self, sender: PrivateKey, recipient: PrivateKey):
        """ should throw an exception if `content` is used """
        with pytest.raises(Exception) as e:
            EncryptedDirectMessage(
                public_key=sender.public_key.hex(),
                content="This is the wrong field",
                recipient_pubkey=recipient.public_key.hex(),
            )

        assert "cannot use" in str(e)
