#!/usr/bin/env python3

"""
client holds the lab client.
"""

import typing as t
import uuid

from server.reference_server import *
from client.log_entry import *
import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors
import requests
from ag.common.mock_http import (
    link_client_server,
)  # imported for doctests, unneeded otherwise


@dataclass
class FriendInfo:
    trusted_keys: t.Set[bytes]
    photos: t.List[bytes]
    last_log_number: int
    last_hash: int
    awaiting_invite: t.Set[bytes]


class Client:
    """The client for the photo-sharing application.

    A client can query a remote server for the list of a user's photos
    as well as the photos themselves.  A client can also add photos on
    behalf of that user.

    A client retains data required to authenticate a user's device
    both to a remote server and to other devices.  To authenticate to
    the remote server, the client presents a username and auth_secret,
    while to authenticate to other devices, the client tags
    updates with an authenticator over the history of all updates.  To
    verify the authenticity of an update, clients check the
    authenticator using a shared symmetric key.
    """

    # maps response RPC name to the corresponding type
    RESPONSE_MAPPINGS: t.Dict[str, types.RpcObject] = {
        "RegisterResponse": types.RegisterResponse,
        "LoginResponse": types.LoginResponse,
        "UpdatePublicProfileResponse": types.UpdatePublicProfileResponse,
        "GetFriendPublicProfileResponse": types.GetFriendPublicProfileResponse,
        "PutPhotoResponse": types.PutPhotoResponse,
        "GetPhotoResponse": types.GetPhotoResponse,
        "PushLogEntryResponse": types.PushLogEntryResponse,
        "SynchronizeResponse": types.SynchronizeResponse,
        "SynchronizeFriendResponse": types.SynchronizeFriendResponse,
    }

    def __init__(
        self,
        username: str,
        remote_url: t.Optional[str] = None,
        user_secret: t.Optional[bytes] = None,
    ) -> None:
        """Initialize a client given a username, a
        remote server's URL, and a user secret.

        If no remote URL is provided, "http://localhost:5000" is assumed.

        If no user secret is provided, this constructor generates a
        new one.
        """
        self._remote_url = remote_url if remote_url else "http://localhost:5000"
        self._client_id = str(uuid.uuid4())

        self._username = username
        self._server_session_token = None

        self._user_secret = crypto.UserSecret(user_secret)

        self._auth_secret = self._user_secret.get_auth_secret()
        self._symmetric_auth = crypto.MessageAuthenticationCode(
            self._user_secret.get_symmetric_key()
        )

        self._public_profile = types.PublicProfile(username)
        self._public_key_signer = (
            crypto.PublicKeySignature()
        )  # not derived from user secret---every device gets its own key pair
        self._photos: t.List[bytes] = []  # list of photos in put_photo order
        self._last_log_number: int = 0
        self._next_photo_id = 0

        self._friends: t.Dict[str, FriendInfo] = {}  # maps usernames to friend state

        self._last_log_hash = hash(None)
        self._device_invite_dict = dict() ## key = inviter, value= set(device invited)
        self._device_added_set = set()
        self._device_revoked_set = set()

    def send_rpc(self, request: types.RpcObject) -> types.RpcObject:
        """
        Sends the given RPC object to the server,
        and returns the server's response.

        To do so, does the following:
        - Converts the given RPC object to JSON
        - Sends a POST request to the server's `/rpc` endpoint
            with the RPC JSON as the body
        - Converts the response JSON into the correct RPC object.

        ## DO NOT CHANGE THIS METHOD

        It is overridden for testing, so any changes will be
        overwritten.
        """
        r = requests.post(f"{self._remote_url}/rpc", json=request.as_rpc_dict())
        resp = r.json()
        resp_type = self.RESPONSE_MAPPINGS.get(resp["rpc"], None)
        if resp_type is None:
            raise ValueError(f'Invalid response type "{resp["rpc"]}".')
        resp = resp_type.from_dict(resp["data"])
        return resp

    @property
    def username(self) -> str:
        """Get the client's username.

        >>> alice = Client("alice")
        >>> alice.username == "alice"
        True
        """
        return self._username

    @property
    def user_secret(self) -> bytes:
        """Get the client's user secret.

        >>> user_secret = crypto.UserSecret().get_secret()
        >>> alice = Client("alice", user_secret=user_secret)
        >>> alice.user_secret == user_secret
        True
        """
        return self._user_secret.get_secret()

    @property
    def public_key(self) -> bytes:
        """Get the client's public key.
        """
        return bytes(self._public_key_signer.public_key)

    def hash_block(self, operation, data, friend_hash = None):
        if friend_hash is None:
            prev = self._last_log_hash
        else:
            prev = friend_hash
        code = prev + hash(str(operation)) + hash(str(data))
        return hash(code)

    def register(self) -> None:
        """Register this client's username with the server,
        initializing the user's state on the server.

        If the client is already registered, raise a
        UserAlreadyExistsError.

        Otherwise, save the session token returned by the server for
        use in future requests.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()
        """
        h = self.hash_block(OperationCode.REGISTER.value, RegisterLogData().encode())
        sign = self._public_key_signer.sign(codec.encode(h))
        log = LogEntry(OperationCode.REGISTER, RegisterLogData().encode(), h, self.public_key, sign)
        req = types.RegisterRequest(
            self._client_id, self._username, self._auth_secret, log.encode()
        )

        resp = self.send_rpc(req)
        assert isinstance(resp, types.RegisterResponse)
        if resp.error is None:
            self._last_log_number += 1
            self._server_session_token = resp.token
            self._last_log_hash = h

        elif resp.error == types.Errcode.USER_ALREADY_EXISTS:
            raise errors.UserAlreadyExistsError(self._username)
        else:
            raise Exception(resp)

    def login(self) -> None:
        """Try to login with to the server with the username and
        auth_secret.

        On success, save the new session token returned by the server
        for use in future requests.

        Otherwise, if the username and auth_secret combination is
        incorrect, raise a LoginFailedError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()

        >>> not_alice = Client("alice", server)
        >>> link_client_server(not_alice, server)
        >>> not_alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        See also: Client.register
        """
        req = types.LoginRequest(
            client_id=self._client_id,
            username=self._username,
            auth_secret=self._auth_secret,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.LoginResponse)
        if resp.error is None:
            self._server_session_token = resp.token
            self._device_added_set.add(self.public_key)
        elif resp.error == types.Errcode.LOGIN_FAILED:
            raise errors.LoginFailedError(self._username)
        else:
            raise Exception(resp)

    # def update_public_profile(self, values: t.Dict[str, t.Any]) -> None:
    #     """Update user public profile with the given fields.
    #     """
    #     # TODO (lab0): Update te local public profile based on the given values and update the server
    #     raise NotImplementedError
    #
    # def get_friend_public_profile(self, friend_username: str) -> types.PublicProfile:
    #     """Obtain the public profile of another user.
    #     """
    #     # TODO (lab0): Fetch and return the public profile of the user friend_username
    #     raise NotImplementedError

    def list_photos(self) -> t.List[int]:
        """Fetch a list containing the photo id of each photo stored
        by the user.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        >>> alice.list_photos()
        [0, 1, 2]
        """
        self._synchronize()

        return list(range(self._next_photo_id))

    def get_photo(self, photo_id) -> bytes:
        """Get a photo by ID.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> photo_id = alice.put_photo(photo_blob)
        >>> photo_id
        0
        >>> alice._fetch_photo(photo_id)
        b'PHOTOOO'
        >>> alice._fetch_photo(1)
        Traceback (most recent call last):
                ...
        common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
        """
        self._synchronize()

        if photo_id < 0 or photo_id >= len(self._photos):
            raise errors.PhotoDoesNotExistError(photo_id)
        return self._photos[photo_id]

    def _push_log_entry(self, log_entry: LogEntry) -> None:
        """
        Push the given log entry to the server
        """
        encoded_log_entry = log_entry.encode()
        req = types.PushLogEntryRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            encoded_log_entry=encoded_log_entry,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.PushLogEntryResponse)
        if resp.error:
            raise errors.RpcError
        self._last_log_hash = log_entry.h
        self._last_log_number += 1

    def _fetch_photo(self, photo_id, user: t.Optional[str] = None) -> bytes:
        """Get a photo from the server using the unique PhotoID.

        If `user` is specified, fetches the photo for the given
        user. Otherwise, fetches for this user.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> photo_id = alice.put_photo(photo_blob)
        >>> photo_id
        0
        >>> alice._fetch_photo(photo_id)
        b'PHOTOOO'
        >>> alice._fetch_photo(1)
        Traceback (most recent call last):
                ...
        common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
        """
        req = types.GetPhotoRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            photo_id=photo_id,
            photo_owner=user or self._username,  # fetch own photo if unspecified
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.GetPhotoResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error == types.Errcode.PHOTO_DOES_NOT_EXIST:
            raise errors.PhotoDoesNotExistError(photo_id)
        elif resp.error is not None:
            raise Exception(resp)
        return resp.photo_blob

    def put_photo(self, photo_blob: bytes):
        """Append a photo_blob to the server's database.

        On success, this returns the unique photo_id associated with
        the newly-added photo.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        """
        self._synchronize()

        photo_id = self._next_photo_id
        h = self.hash_block(OperationCode.PUT_PHOTO.value, PutPhotoLogData(photo_id).encode()+photo_blob)
        sign = self._public_key_signer.sign(codec.encode(h))
        log = LogEntry(OperationCode.PUT_PHOTO, PutPhotoLogData(photo_id).encode(), h,
                       self.public_key, sign)
        req = types.PutPhotoRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            encoded_log_entry=log.encode(),
            photo_blob=photo_blob,
            photo_id=photo_id,
        )

        resp = self.send_rpc(req)
        assert isinstance(resp, types.PutPhotoResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)

        self._record_new_photo(photo_blob)
        self._last_log_number += 1
        self._last_log_hash = h
        return photo_id

    def _record_new_photo(self, photo_blob):
        """
        Locally record a new photo.
        """
        self._next_photo_id += 1
        self._photos.append(photo_blob)

    def verify_signer(self, h, log: LogEntry):
        if not crypto.verify_sign(log.pk, codec.encode(h), log.signature):
            raise errors.SynchronizationError("Pk Signature doesn't match")
        if log.pk not in self._device_added_set and log.opcode not in {1, 4}:
            # in registration we still haven't added the device
            # when a device accepts invite they will push log abd only then other devices will be able to add
            raise errors.SynchronizationError("device not allowed to add log")

    def _synchronize(self):
        """Synchronize the client's state against the server.

        On failure, this raises a SynchronizationError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> user_secret = alice.user_secret
        >>> alicebis = Client("alice", server, user_secret)
        >>> link_client_server(alicebis, server)
        >>> alicebis.login()
        >>> alicebis._synchronize()
        >>> alice.login()
        >>> photo_blob = b'PHOTOOO'
        >>> alice._synchronize()
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> alicebis.login()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis._synchronize()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis.put_photo(photo_blob)
        2
        """
        req = types.SynchronizeRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            min_version_number=self._last_log_number,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.SynchronizeResponse)

        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error == types.Errcode.VERSION_TOO_HIGH:
            raise errors.SynchronizationError(errors.VersionTooHighError())
        elif resp.error is not None:
            raise Exception(resp)

        for encoded in resp.encoded_log_entries:
            try:
                log = LogEntry.decode(encoded)
            except errors.MalformedEncodingError as e:
                raise errors.SynchronizationError(e)
            if log.opcode == OperationCode.REGISTER.value:
                h = self.hash_block(log.opcode, log.data)
                if h == log.h:
                    self.verify_signer(h, log)
                    self._last_log_hash = h
                    self._device_added_set.add(log.pk)
                else:
                    raise errors.SynchronizationError("Registration Hash does not match!")
            if log.opcode == OperationCode.PUT_PHOTO.value:
                log_data = PutPhotoLogData.decode(log.data)
                photo_blob = self._fetch_photo(log_data.photo_id)
                h = self.hash_block(log.opcode, log.data+photo_blob)

                if h == log.h:
                    self.verify_signer(h, log)
                    self._record_new_photo(photo_blob)
                    self._last_log_hash = h
                else:
                    raise errors.SynchronizationError("Issue with photos uploaded!")

            if log.opcode == OperationCode.DEVICE_INVITE.value:
                h = self.hash_block(log.opcode, log.data)
                if h == log.h:
                    self.verify_signer(h, log)
                    if log.pk in self._device_invite_dict:
                        self._device_invite_dict[log.pk].add(log.data)
                    else:
                        self._device_invite_dict[log.pk] = {log.data}
                    self._last_log_hash = h
                else:
                    raise errors.SynchronizationError("device invite log doesn't match")

            if log.opcode == OperationCode.DEVICE_ADDED.value:
                h = self.hash_block(log.opcode, log.data)
                if h == log.h:
                    self.verify_signer(h, log)
                    self.remove_invite(log.pk)
                    self._device_added_set.add(log.pk)
                    self._last_log_hash = h

            if log.opcode == OperationCode.DEVICE_REVOKED.value:
                h = self.hash_block(log.opcode, log.data)
                if h == log.h:
                    self.verify_signer(h, log)
                    self.remove_invite(log.data)
                    if log.data in self._device_added_set and log.data != self.public_key:
                        self._device_added_set.remove(log.data)
                        self._device_revoked_set.add(log.data)
                    self._last_log_hash = h
            self._last_log_number += 1

    def remove_invite(self, pk):
        for inviter, invitee in self._device_invite_dict.items():
            if pk in invitee:
                invitee.remove(pk)

    def invite_device(self, device_public_key: bytes) -> None:
        self._synchronize()
        # h = self.hash_block(OperationCode.PUT_PHOTO.value, PutPhotoLogData(photo_id).encode() + photo_blob)
        # some pk wants to add a device
        # my data is the other device pk
        h = self.hash_block(OperationCode.DEVICE_INVITE.value, device_public_key)
        sign = self._public_key_signer.sign(codec.encode(h))
        log = LogEntry(OperationCode.DEVICE_INVITE, device_public_key, h, self.public_key, sign)
        self._push_log_entry(log)
        if device_public_key in self._device_revoked_set:
            self._device_revoked_set.remove(device_public_key)
        if log.pk in self._device_invite_dict:
            self._device_invite_dict[log.pk].add(log.data)
            # print("Deviced added to invite list")
        else:
            # print("Deviced added to invite list")
            self._device_invite_dict[log.pk] = {log.data}

    def accept_invite(self, inviter_public_key: bytes) -> None:
        self._synchronize()
        if inviter_public_key not in self._device_invite_dict:
            pass
        elif self.public_key in self._device_invite_dict[inviter_public_key]:
            h = self.hash_block(OperationCode.DEVICE_ADDED.value, self.public_key)
            sign = self._public_key_signer.sign(codec.encode(h))
            log = LogEntry(OperationCode.DEVICE_ADDED, self.public_key, h, self.public_key, sign)
            self._push_log_entry(log)
            self._device_added_set.add(self.public_key)
            self.remove_invite(self.public_key)
            # print("Device was found and invite list and accepted")
        # else:
        #     raise errors.SynchronizationError("Device not invited")

    def revoke_device(self, device_public_key: bytes) -> None:
        self._synchronize()
        h = self.hash_block(OperationCode.DEVICE_REVOKED.value, device_public_key)
        sign = self._public_key_signer.sign(codec.encode(h))
        log = LogEntry(OperationCode.DEVICE_REVOKED, device_public_key, h, self.public_key, sign)
        self._push_log_entry(log)
        self.remove_invite(device_public_key)
        if device_public_key in self._device_added_set and device_public_key != self.public_key:
            self._device_added_set.remove(device_public_key)
            self._device_revoked_set.add(device_public_key)

    def add_friend(self, friend_username: str, friend_public_key: bytes) -> None:
        """
        Adds the person with the given username to the local
        friends list, marking the given public key as trusted.

        If the friend already exists, overwrites their public key
        with the provided one.
        """
        self._friends[friend_username] = FriendInfo(set([friend_public_key]), [], 0, hash(None), set())

    def get_friend_photos(self, friend_username) -> t.List[bytes]:
        self._synchronize_friend(friend_username)
        return self._friends[friend_username].photos

    # @dataclass
    # class FriendInfo:
    #     trusted_keys: t.Set[bytes]
    #     photos: t.List[bytes]
    #     last_log_number: int
    #     last_hash: int
    #     awaiting_invite: t.Set[bytes]

    def _synchronize_friend(self, friend_username: str):
        """
        Update the state of the given friend locally
        based on the friend's log in the server.
        """
        if friend_username not in self._friends:
            raise errors.UnknownUserError(friend_username)
        friend_info = self._friends[friend_username]
        req = types.SynchronizeFriendRequest(
            self._client_id, friend_username, friend_info.last_log_number
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.SynchronizeFriendResponse)

        if resp.error == types.Errcode.VERSION_TOO_HIGH:
            raise errors.SynchronizationError(errors.VersionTooHighError())
        elif resp.error is not None:
            raise Exception(resp)

        for encoded in resp.encoded_friend_log_entries:
            try:
                log = LogEntry.decode(encoded)
            except errors.MalformedEncodingError as e:
                raise errors.SynchronizationError(e)
            if friend_info.last_log_number == 0 and log.opcode == OperationCode.REGISTER.value:
                h = self.hash_block(log.opcode, log.data, friend_info.last_hash)
                if h == log.h:
                    if crypto.verify_sign(log.pk, codec.encode(h), log.signature):
                        friend_info.trusted_keys.add(log.pk)
                        friend_info.last_hash = h
                    else:
                        raise errors.SynchronizationError("signature doesn't pass")
                else:
                    raise errors.SynchronizationError("hash doesn't match")
            else:
                errors.SynchronizationError("Registration not at start")
            if log.opcode == OperationCode.PUT_PHOTO.value:
                log_data = PutPhotoLogData.decode(log.data)
                photo_blob = self._fetch_photo(log_data.photo_id, friend_username)
                h = self.hash_block(log.opcode, log.data+photo_blob, friend_info.last_hash)
                self.friend_check("PUT PHOTO", log, h, friend_info)
                friend_info.photos.append(photo_blob)
                friend_info.last_hash = h
            if log.opcode == OperationCode.DEVICE_INVITE.value:
                h = self.hash_block(log.opcode, log.data, friend_info.last_hash)
                self.friend_check("INVITE", log, h, friend_info)
                friend_info.awaiting_invite.add(log.data)
                friend_info.last_hash = h
            if log.opcode == OperationCode.DEVICE_ADDED.value:
                h = self.hash_block(log.opcode, log.data, friend_info.last_hash)
                self.friend_check("ADDED", log, h, friend_info)
                friend_info.awaiting_invite.remove(log.data)
                friend_info.trusted_keys.add(log.data)
                friend_info.last_hash = h
            if log.opcode == OperationCode.DEVICE_REVOKED.value:
                h = self.hash_block(log.opcode, log.data, friend_info.last_hash)
                self.friend_check("REVOKED", log, h, friend_info)
                if log.data in friend_info.trusted_keys:
                    friend_info.trusted_keys.remove(log.data)
                if log.data in friend_info.awaiting_invite:
                    friend_info.awaiting_invite.remove(log.data)
                friend_info.last_hash = h

            friend_info.last_log_number += 1

    def friend_check(self, stage, log, h, friend_info):
        if h != log.h:
            raise errors.SynchronizationError("{} Hash doesn't match".format(stage))
        if not crypto.verify_sign(log.pk, codec.encode(h), log.signature):
            raise errors.SynchronizationError("{}: Message sign not match".format(stage))
        if log.pk not in friend_info.trusted_keys and stage != "ADDED":
            raise errors.SynchronizationError("{}: Image from untrusted user".format(stage))
        if stage == "ADDED":
            if log.pk not in friend_info.awaiting_invite:
                raise errors.SynchronizationError("{}: Not on invite list".format(stage))

