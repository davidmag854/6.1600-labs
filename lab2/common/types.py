#!/usr/bin/env python3

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from enum import IntEnum, auto, unique

import typing as t

import common.codec as codec

"""
A common API between the client and the server.
"""


@unique
class Errcode(IntEnum):
    UNKNOWN = auto()
    USER_ALREADY_EXISTS = auto()
    LOGIN_FAILED = auto()
    INVALID_TOKEN = auto()
    VERSION_TOO_LOW = auto()
    VERSION_TOO_HIGH = auto()
    PHOTO_DOES_NOT_EXIST = auto()


PublicProfile = t.Dict[str, t.Any]


TRpc = t.TypeVar("TRpc", bound="RpcObject")


class RpcDict(t.TypedDict):
    rpc: str
    data: t.Dict[str, t.Any]


class RpcObject:
    def as_rpc_dict(self) -> RpcDict:
        """
        Converts the object into the dict format expected by the RPC server.

        Includes an "rpc" key with the name of the RPC, and a "data"
        key that contains the RpcObject content itself as a dict.
        """
        return {"rpc": self.__class__.__name__, "data": self.as_dict()}

    def as_dict(self):
        """
        Automatically converts this object and any children
        to a serializable dictionary by recursively calling as_dict.

        Handles values of types RpcObject or list, or base python types

        May need to be overridden for special types.
        """

        def serialize_list_items(l: t.List) -> t.List:
            return [
                v.as_dict
                if isinstance(v, RpcObject)
                else f"base64:{b64encode(v).decode('UTF-8')}"
                if isinstance(v, bytes)
                else v
                for v in l
            ]

        result = {
            k: v.as_dict()
            if isinstance(v, RpcObject)
            else f"base64:{b64encode(v).decode('UTF-8')}"
            if isinstance(v, bytes)
            else serialize_list_items(v)
            if isinstance(v, list)
            else v
            for k, v in self.__dict__.items()
        }
        return result

    @classmethod
    def from_dict(cls: TRpc, data: t.Dict[str, t.Any]) -> TRpc:
        """
        Reconstruct the given type from the serialized (as a dict)
        representation of that type.

        If as_dict is overridden for a particular class, this should
        be as well to match.
        """

        def deserialize_list_items(l: t.List) -> t.List:
            return [
                b64decode(v[7:]) if isinstance(v, str) and v[:7] == "base64:" else v
                for v in l
            ]

        # This does not do any type checking! We could, though.
        return cls(
            **{
                k: b64decode(v[7:])
                if isinstance(v, str) and v[:7] == "base64:"
                else deserialize_list_items(v)
                if isinstance(v, list)
                else v
                for k, v in data.items()
            }
        )

    @staticmethod
    def from_rpc_dict(data: RpcDict) -> "RpcObject":
        """
        Convert the given rpc-formatted dictionary object (generated by as_rpc_dict)
        into an instance of one of the rpc objects
        """
        subclass = {c.__name__ for c in RpcObject.__subclasses__}.get(data["rpc"])
        if subclass is None:
            raise ValueError(f'Invalid RPC Type "{data["rpc"]}"')
        return subclass.from_dict(data["data"])


@dataclass
class PublicProfile(RpcObject):
    username: str
    profile: t.Dict[str, t.Any] = field(default_factory=dict)


@dataclass
class RequestError(RpcObject):
    """An error returned by a request, identified with an error code and extra information."""

    error_code: Errcode
    info: str


@dataclass
class Request(RpcObject):
    """Any request to the server should inherit from this"""

    client_id: str


@dataclass
class AuthenticatedRequest(Request):
    """A request including authentication information (a token)"""

    username: str
    token: bytes


@dataclass
class Response(RpcObject):
    error: t.Union[Errcode, None]


@dataclass
class PushLogEntryRequest(AuthenticatedRequest):  # TODO: make naming clearer
    """
    A request for the server to add the given log
    entry to the authenticated user's log.
    """

    encoded_log_entry: bytes


@dataclass
class PushLogEntryResponse(Response):
    pass


@dataclass
class RegisterRequest(Request):
    username: str
    auth_secret: bytes
    encoded_log_entry: bytes


@dataclass
class RegisterResponse(Response):
    """The register response is composed of an error code (indicating if the registration was successful and a session token"""

    token: bytes


@dataclass
class LoginRequest(Request):
    username: str
    auth_secret: bytes


@dataclass
class LoginResponse(Response):
    token: bytes


@dataclass
class UpdatePublicProfileRequest(AuthenticatedRequest):
    public_profile: PublicProfile

    @classmethod
    def from_dict(cls, data: t.Dict[str, t.Any]) -> "UpdatePublicProfileRequest":
        client_id = data["client_id"]
        username = data["username"]
        token = data["token"]
        public_profile = PublicProfile.from_dict(data["public_profile"])
        return cls(
            client_id=client_id,
            username=username,
            token=token,
            public_profile=public_profile,
        )


@dataclass
class UpdatePublicProfileResponse(Response):
    pass


@dataclass
class GetFriendPublicProfileRequest(AuthenticatedRequest):
    friend_username: str


@dataclass
class GetFriendPublicProfileResponse(Response):
    public_profile: PublicProfile

    @classmethod
    def from_dict(cls, data: t.Dict[str, t.Any]) -> "UpdatePublicProfileRequest":
        error = data["error"]
        public_profile = PublicProfile.from_dict(data["public_profile"])
        return cls(
            error=error,
            public_profile=public_profile,
        )


@dataclass
class PutPhotoRequest(PushLogEntryRequest):
    photo_blob: bytes
    photo_id: int


@dataclass
class PutPhotoResponse(Response):
    pass


@dataclass
class GetPhotoRequest(AuthenticatedRequest):
    photo_id: int
    photo_owner: str


@dataclass
class GetPhotoResponse(Response):
    photo_blob: bytes


@dataclass
class SynchronizeRequest(AuthenticatedRequest):
    min_version_number: int


@dataclass
class SynchronizeResponse(Response):
    encoded_log_entries: t.List[bytes]


@dataclass
class SynchronizeFriendRequest(Request):
    """
    A request asking the server to respond with the given
    friend's log, starting from the given `min_log_number`
    """

    friend_username: str
    min_version_number: int  # the lowest log number to include in the response


@dataclass
class SynchronizeFriendResponse(Response):
    """
    A request asking the server to respond with the given
    friend's log.
    """

    encoded_friend_log_entries: t.List[bytes]

