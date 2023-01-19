import json
import random
from binascii import hexlify

from .filter import Filters
from .message_type import ClientMessageType



class Subscription:

    def __init__(self, id: str = None, filters: Filters=None) -> None:
        if id is None:
            # NIP-01: subscription_id is a random string
            self.id = hexlify(random.randbytes(32)).decode()
        else:
            self.id = id
        self.filters = filters


    def to_json_object(self):
        return { 
            "id": self.id, 
            "filters": self.filters.to_json_array() 
        }
    

    def to_message(self):
        request = [ClientMessageType.REQUEST, self.id]
        request.extend(self.filters.to_json_array())
        return json.dumps(request)
