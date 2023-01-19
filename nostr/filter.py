from collections import UserList
from typing import List

from .event import Event



class Filter:
    def __init__(
            self, 
            ids: "list[str]" = None, 
            kinds: "list[int]" = None, 
            authors: "list[str]" = None, 
            since: int = None, 
            until: int = None, 
            event_refs: List[str] = None,       # the "#e" attr; list of event ids referenced in an "e" tag
            pubkey_refs: List[str] = None,      # The "#p" attr; lost of pubkeys referenced in a "p" tag
            limit: int = None) -> None:
        self.IDs = ids
        self.kinds = kinds
        self.authors = authors
        self.since = since
        self.until = until
        self.event_refs = event_refs
        self.pubkey_refs = pubkey_refs
        self.limit = limit


    def matches(self, event: Event) -> bool:
        if self.IDs != None and event.id not in self.IDs:
            return False
        if self.kinds != None and event.kind not in self.kinds:
            return False
        if self.authors != None and event.public_key not in self.authors:
            return False
        if self.since != None and event.created_at < self.since:
            return False
        if self.until != None and event.created_at > self.until:
            return False
        if (self.event_refs is not None or self.pubkey_refs is not None) and len(event.tags) == 0:
            return False
        if self.event_refs is not None:
            for event_id in [tag[1] for tag in event.tags if tag[0] == "e"]:
                if event_id not in self.event_refs:
                    return False
        if self.pubkey_refs is not None:
            for pubkey in [tag[1] for tag in event.tags if tag[0] == "p"]:
                if pubkey not in self.pubkey_refs:
                    return False
        return True


    def to_json_object(self) -> dict:
        res = {}
        if self.IDs != None:
            res["ids"] = self.IDs
        if self.kinds != None:   
            res["kinds"] = self.kinds
        if self.authors != None:
            res["authors"] = self.authors
        if self.since != None:
            res["since"] = self.since
        if self.until != None:
            res["until"] = self.until
        if self.event_refs != None:
            res["#e"] = self.event_refs
        if self.pubkey_refs != None:
            res["#p"] = self.pubkey_refs
        if self.limit != None:
            res["limit"] = self.limit

        return res



class Filters(UserList):
    def __init__(self, initlist: "list[Filter]"=[]) -> None:
        super().__init__(initlist)
        self.data: "list[Filter]"

    def match(self, event: Event):
        for filter in self.data:
            if filter.matches(event):
                return True
        return False

    def to_json_array(self) -> list:
        return [filter.to_json_object() for filter in self.data]
