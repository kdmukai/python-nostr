import time
import threading
from websocket import WebSocketConnectionClosedException
from .event import Event
from .filter import Filters
from .message_pool import MessagePool
from .message_type import ClientMessageType
from .relay import Relay, RelayPolicy
from .subscription import Subscription



class RelayException(Exception):
    pass





class RelayException(Exception):
    pass



class RelayManager:

    def __init__(self, ssl_options: dict = None, try_reconnect: bool = True, proxy: dict = {}) -> None:
        self.ssl_options = ssl_options
        self.try_reconnect = try_reconnect
        self.proxy = proxy
        self.relays: dict[str, Relay] = {}
        self.message_pool = MessagePool()


    def add_relay(self, url: str, read: bool=True, write: bool=True, subscriptions={}):
        policy = RelayPolicy(read, write)
        relay = Relay(url, policy, self.message_pool, subscriptions, ssl_options=self.ssl_options)
        self.relays[url] = relay


    def remove_relay(self, url: str):
        self.relays.pop(url)


    def add_subscription(self, subscription: Subscription):
        for relay in self.relays.values():
            relay.add_subscription(subscription)


    def close_subscription(self, id: str):
        for relay in self.relays.values():
            relay.close_subscription(id)


    def open_connection(self, relay: Relay):
        threading.Thread(
            target=relay.connect,
            name=f"{relay.url}-thread",
            daemon=True,  # force threads to exit on main thread shutdown or crash
        ).start()


    def open_connections(self):
        for relay in self.relays.values():
            self.open_connection(relay)


    def close_connections(self):
        for relay in self.relays.values():
            relay.close()


    def publish_message(self, message: str):
        for relay in self.relays.values():
            if relay.policy.should_write:
                try:
                    relay.publish(message)
                except WebSocketConnectionClosedException:
                    print(f"Attempting to reconnect to {relay.url}")
                    self.open_connection(relay)


    def publish_event(self, event: Event):
        """ Verifies that the Event is publishable before submitting it to relays """
        if event.signature is None:
            raise RelayException(f"Could not publish {event.id}: must be signed")

        if not event.verify():
            raise RelayException(f"Could not publish {event.id}: failed to verify signature {event.signature}")

        self.publish_message(event.to_message())
