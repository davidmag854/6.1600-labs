#!/usr/bin/env python3

"""
client holds the lab client.
"""

import copy
import typing as t
import uuid

from server.reference_server import *
from client.log_entry import *
import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors
import requests

# imported for doctests, unneeded otherwise
from ag.common.mock_http import (
    link_client_server,
)  

@dataclass
class FriendInfo:
    pk: bytes
    trusted_keys: t.Set[bytes]
    photos: t.List[bytes]
    last_log_number: int
    last_hash: int
    awaiting_invite: t.Set[bytes]


class ExtendedProfileContent(types.ProfileContents):
    MAC_pk: bytes



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
        "GetAlbumResponse": types.GetAlbumResponse,
        "UploadAlbumResponse": types.UploadAlbumResponse,
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

        # self._device_public_key_signer = (
        #     crypto.PublicKeySignature()
        # )  # not derived from user secret---every device gets its own key pair

        self._photos: t.List[bytes] = []  # list of photos in put_photo order
        self._last_log_number: int = 0
        self._next_photo_id = 0

        # LAB 2
        self._friends: t.Dict[str, FriendInfo] = {}  # maps usernames to friend state
        self._last_log_hash = hash(None)
        self._device_invite_dict = dict() ## key = inviter, value= set(device invited)
        self._device_added_set = set()
        self._device_revoked_set = set()

        # LAB 3
        self._public_key_signer = crypto.PublicKeySignature(
            self._user_secret.get_signing_secret_key()
        )
        self._authenticated_encryption = crypto.PublicKeyEncryptionAndAuthentication(
            self._user_secret.get_encrypt_and_auth_secret_key()
        )
        self._albums: t.Dict[str, Album] = {}  # maps album name to album contents
        self._album_keys: t.Dict[str, int] = {}
        self._public_profile = types.PublicProfile(
            username=username,
            contents=ExtendedProfileContent(
                encrypt_public_key=self.encryption_public_key,
                MAC_pk=self.signing_public_key
            ),
            metadata=self._public_key_signer.sign(
                self.pack_and_hash(self.encryption_public_key, self.signing_public_key))
        )



    @staticmethod
    def pack_and_hash(*data):
        h = hash(None)
        for d in data:
            h = hash(hash(d)+h)
        return codec.encode(h)

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
        print("RPC DICT", request.as_rpc_dict())
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
    def signing_public_key(self) -> bytes:
        """Get the client's public key."""
        return self._public_key_signer.public_key

    @property
    def encryption_public_key(self) -> bytes:
        """
        Get the client's public key to be used for authenticated encryption
        """
        return bytes(self._authenticated_encryption.public_key)

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
        log = LogEntry(
            opcode=OperationCode.REGISTER,
            data=RegisterLogData().encode(),
            h=h,
            public_key=self.signing_public_key,
            signature=sign)
        req = types.RegisterRequest(
            self._client_id,
            self._username,
            self._auth_secret,
            self._public_profile,
            log.encode(),
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
        elif resp.error == types.Errcode.LOGIN_FAILED:
            raise errors.LoginFailedError(self._username)
        else:
            raise Exception(resp)

    def update_public_profile(self, values: t.Dict[str, t.Any]) -> None:
        """Update user public profile with the given fields."""
        # TODO (lab0): Update te local public profile based on the given values and update the server
        self._public_profile["contents"].update(values)
        self._public_profile["metadata"] = self._public_key_signer.sign(self.pack_and_hash(*values.values()))
        req = types.UpdatePublicProfileRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            public_profile=self._public_profile,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.UpdatePublicProfileResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)

    def get_friend_public_profile(self, friend_username: str) -> types.PublicProfile:
        """Obtain the public profile of another user.

        The user must be a "friend" (i.e. added by `add_friend()`)
        """
        # TODO (lab0): Fetch and return the public profile of the user friend_username
        if friend_username != self.username and friend_username not in self._friends:
            raise errors.UnknownUserError(friend_username)
        if friend_username == self.username:
            return self._public_profile
        req = types.GetFriendPublicProfileRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            friend_username=friend_username,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.GetFriendPublicProfileResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)
        else:
            # get sign key of friend
            friend_pk = self._friends.get(friend_username).pk
            # check the signature in metadata is verified by
            data = self.pack_and_hash(*resp.public_profile["contents"].values())
            if not crypto.verify_sign(
                pk=friend_pk,
                data=data,
                signature=resp.public_profile["metadata"]
            ):
                raise errors.SynchronizationError("Public profile signature doesn't match")
            return resp.public_profile

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
                       self.signing_public_key, sign)
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
                    if log.data in self._device_added_set and log.data != self.signing_public_key:
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
        log = LogEntry(OperationCode.DEVICE_INVITE, device_public_key, h, self.signing_public_key, sign)
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
        elif self.signing_public_key in self._device_invite_dict[inviter_public_key]:
            h = self.hash_block(OperationCode.DEVICE_ADDED.value, self.signing_public_key)
            sign = self._public_key_signer.sign(codec.encode(h))
            log = LogEntry(OperationCode.DEVICE_ADDED, self.signing_public_key, h, self.signing_public_key, sign)
            self._push_log_entry(log)
            self._device_added_set.add(self.signing_public_key)
            self.remove_invite(self.signing_public_key)
            # print("Device was found and invite list and accepted")
        # else:
        #     raise errors.SynchronizationError("Device not invited")

    def revoke_device(self, device_public_key: bytes) -> None:
        self._synchronize()
        h = self.hash_block(OperationCode.DEVICE_REVOKED.value, device_public_key)
        sign = self._public_key_signer.sign(codec.encode(h))
        log = LogEntry(OperationCode.DEVICE_REVOKED, device_public_key, h, self.signing_public_key, sign)
        self._push_log_entry(log)
        self.remove_invite(device_public_key)
        if device_public_key in self._device_added_set and device_public_key != self.signing_public_key:
            self._device_added_set.remove(device_public_key)
            self._device_revoked_set.add(device_public_key)

    def add_friend(
        self, friend_username: str, friend_signing_public_key: bytes
    ) -> None:
        """
        Adds the person with the given username to the local
        friends list, marking the given public key as trusted.

        If the friend already exists, overwrites their public key
        with the provided one.
        """
        self._friends[friend_username] = FriendInfo(friend_signing_public_key, set(), [], 0, hash(None), set())

    def get_friend_photos(self, friend_username) -> t.List[bytes]:
        self._synchronize_friend(friend_username)
        return self._friends[friend_username].photos

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
                        # if friend_info.pk != log.pk:
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
            if log.opcode == OperationCode.ALBUM_KEY.value:
                h = self.hash_block(log.opcode, log.data, friend_info.last_hash)
                self.friend_check("ALBUM", log, h, friend_info)
                friend_info.last_hash=h
                # check if the message is for me
                if log.pk == self._authenticated_encryption.public_key:
                    # get friend pk
                    friend_pp = self.get_friend_public_profile(friend_username)
                    friend_auth_pk = friend_pp["contents"]["encrypt_public_key"]
                    # if the messsage is for me decrypt the message
                    dec_data = self._authenticated_encryption.decrypt_and_verify(
                        ciphertext=log.data,
                        friend_pk=friend_auth_pk
                    )
                    dec_data = codec.decode(dec_data)
                    album_name = dec_data[0]
                    album_key = dec_data[1]
                    self._album_keys[album_name] = album_key

            friend_info.last_log_number += 1

    @staticmethod
    def friend_check(stage, log, h, friend_info):
        if h != log.h:
            raise errors.SynchronizationError("{} Hash doesn't match".format(stage))
        uploader_pk = log.pk
        if stage == "ALBUM":
            uploader_pk = friend_info.pk
        if not crypto.verify_sign(uploader_pk, codec.encode(h), log.signature):
            raise errors.SynchronizationError("{}: Message sign not match".format(stage))
        if uploader_pk not in friend_info.trusted_keys and stage not in {"ADDED", "ALBUM"}:
            raise errors.SynchronizationError("{}: Image from untrusted user".format(stage))
        if stage == "ADDED":
            if uploader_pk not in friend_info.awaiting_invite:
                raise errors.SynchronizationError("{}: Not on invite list".format(stage))

    @staticmethod
    def decrypt_album(key, album:t.List[bytes]):
        dec_album = []
        decrypter = crypto.SymmetricKeyEncryption(key)
        for photo in album:
            dec_album.append(decrypter.decrypt(photo))
        return dec_album

    @staticmethod
    def encrypt_album(key, album:t.List[bytes]):
        enc_album = []
        encrypter = crypto.SymmetricKeyEncryption(key)
        for photo in album:
            enc_album.append(encrypter.encrypt(photo))
        return enc_album

    @staticmethod
    def create_album_symmetric_key():
        return crypto.SymmetricKeyEncryption()

    def publish_album_key_to_friends(self, album_name, album, friends:t.List[types.PublicProfile], key):
        # for every friend that is added sign
        for friend_public_profile in friends:
            album_friend_signature = self._public_key_signer.sign(codec.encode(hash(friend_public_profile["username"])))
            album.metadata[friend_public_profile["username"]] = album_friend_signature
            album.metadata[friend_public_profile["username"]+"_key"] = self._authenticated_encryption.encrypt_and_auth(
                data=key,
                friend_pk=friend_public_profile["contents"]["encrypt_public_key"]
            )
            data = [album_name, key]
            # send key to friend
            log_data = self._authenticated_encryption.encrypt_and_auth(
                data=codec.encode(data),
                friend_pk=friend_public_profile["contents"]["encrypt_public_key"]
            )
            log_h = self.hash_block(
                operation=OperationCode.ALBUM_KEY.value,
                data=log_data
            )
            # log signed with owner's friend info pk
            log_signature = self._public_key_signer.sign(codec.encode(log_h))
            log_public_key_recepient_autnenc_pk = friend_public_profile["contents"]["encrypt_public_key"]
            log = LogEntry(
                opcode=OperationCode.ALBUM_KEY,
                data=log_data,
                public_key=log_public_key_recepient_autnenc_pk,
                signature=log_signature,
                h=log_h
            )
            self._push_log_entry(log)

    def sync_all_friends(self):
        for friend in self._friends.keys():
            if friend != self.username:
                self._synchronize_friend(friend)

    def create_shared_album(
        self, album_name: str, photos: t.List[bytes], friends: t.List[str]
    ):
        """Create a new private album with name name_album photos in photos
        The album will be uploaded to the server.
        The photos should only be accessible to the users listed in friends.

        All friends in `friends` must have been added to this device via `add_friend()` beforehand.
        """
        self.sync_all_friends()
        friends_pp_mapping = {
            username: self.get_friend_public_profile(username) for username in friends
        }
        # friends_pp_mapping key = username
        # friends_pp_mapping value = verified friend public profile
        if self.username not in friends_pp_mapping:
            friends_pp_mapping[self.username] = self._public_profile
        album = Album(
            photos=photos, owner=self.username, friends=friends_pp_mapping, metadata={}
        )
        self._albums[album_name] = album
        # create album symmetric key
        key = crypto.generate_symmetric_secret_key()
        # save key locally
        self._album_keys[album_name] = key
        # send key to all of my friends
        self.publish_album_key_to_friends(album_name=album_name, album=album, friends=friends_pp_mapping.values(), key=key)
        self._upload_album(album_name)

    def _upload_album(self, album_name: str):
        self.sync_all_friends()
        album = self._albums[album_name]
        # copy album so locally we will have the decrypted version
        album = Album.from_dict(album.as_dict())
        # Check album key exist
        if album_name not in self._album_keys.keys():
            # raise errors.AlbumPermissionError(album_name)
            return
        # get album key
        key = self._album_keys[album_name]
        # encrypt all photos
        album.photos = self.encrypt_album(key, album.photos)
        # upload encrypted version
        req = types.UploadAlbumRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            album_name,
            album.as_dict(),
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.UploadAlbumResponse)

        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)

    def get_album(self, album_name: str) -> types.PhotoAlbumDict:
        """Get an album from the server using its name and the owner's username.
        If the client is part of the friends given access to the album, it will have access to the photos.

        Note: the owner must have been added as a friend to the device using add_friend.
        """
        self.sync_all_friends()
        req = types.GetAlbumRequest(
            self._client_id, self._username, self._server_session_token, album_name
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.GetAlbumResponse)

        if (
            resp.album["owner"] != self.username
            and resp.album["owner"] not in self._friends
        ):
            raise errors.AlbumOwnerError(resp.album["owner"])

        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        if resp.error == types.Errcode.ALBUM_DOES_NOT_EXIST:
            raise errors.AlbumPermissionError(album_name)
        elif resp.error is not None:
            raise Exception(resp)

        if self._username not in resp.album["friends"]:
            raise errors.AlbumPermissionError(album_name)
        if album_name not in self._album_keys:
            raise errors.AlbumPermissionError(album_name)
        # get key locally
        key = self._album_keys[album_name]
        # take album from resp
        album = Album.from_dict(resp.album)
        # making sure that the album saved locally only has valid friends
        if resp.album["owner"] == self.username:
            owner_pk = self.signing_public_key
        else:
            owner_pk = self._friends[resp.album["owner"]].pk
        album.veirfy_friends(owner_pk)
        album.photos = self.decrypt_album(key, album.photos)
        self._albums[album_name] = album
        # this should return the decrypted album
        return self._albums[album_name].as_dict()

    def add_friend_to_album(self, album_name: str, friend_username: str):
        """Add a friend to an existing album with name album_name.
        Only the owner of the album can modify the list of friends.

        Note: the friend must have been added as a friend to the device using add_friend.
        If they are not, raise an errors.UnknownUserError.
        """
        self.sync_all_friends()
        if friend_username not in self._friends:
            raise errors.UnknownUserError(friend_username)

        if not self._albums[album_name].owner == self.username:
            return errors.AlbumOwnerError(album_name)

        if album_name not in self._album_keys:
            raise errors.AlbumPermissionError(album_name)
        self.get_album(album_name)
        friend_pp = self.get_friend_public_profile(friend_username)
        # print(f"{self.username} Trying to add {friend_pp}")
        # add friend to album
        self._albums[album_name].add_friend(friend_pp)
        # send album key to friend + add friend signature
        key = self._album_keys[album_name]
        # print(f"Album key is {key}")
        self.publish_album_key_to_friends(album_name, self._albums[album_name], [friend_pp], key)
        # upload the new album to friend
        self._upload_album(album_name)

    def remove_friend_from_album(self, album_name: str, friend_username: str):
        """Add a friend to an existing album with name album_name.
        Only the owner of the album can modify the list of friends.
        """
        self.sync_all_friends()
        if not self._albums[album_name].owner == self.username:
            return errors.AlbumOwnerError(album_name)
        self.get_album(album_name)
        self._albums[album_name].remove_friend(friend_username)
        # need to generate new key!
        new_key = crypto.generate_symmetric_secret_key()
        # update key
        self._album_keys[album_name] = new_key
        # remove friend from album locally
        self._albums[album_name].remove_friend(friend_username)
        # verify all current friend were added by owner
        self._albums[album_name].veirfy_friends(self._public_key_signer.public_key)
        # send new key to verified friends
        self.publish_album_key_to_friends(
            album_name=album_name,
            album=self._albums[album_name],
            friends=self._albums[album_name].friends.values(),
            key=new_key)
        self._upload_album(album_name)

    def add_photo_to_album(self, album_name: str, photo: bytes):
        """Add a photo to an existing album with name album_name.
        Only friends of the album can add photos.

        Note: the owner of the album must have been added as a friend on this device.
        """
        self.sync_all_friends()
        self.get_album(album_name)
        album = self._albums[album_name]
        if album.owner == self.username:
            owner_pk = self.signing_public_key
        else:
            owner_pk = self._friends[album.owner].pk
        album.veirfy_friends(owner_pk)

        if self.username in album.friends.keys():
            album.add_photo(photo)
        self._upload_album(album_name)


@dataclass
class Album:
    """
    A class to make it easier to generate and modify photo albums
    """

    photos: t.List[bytes]
    owner: str
    friends: t.Dict[str, types.PublicProfile]  # username to public profile
    metadata: t.Dict[str, t.Any]

    def as_dict(self) -> types.PhotoAlbumDict:
        return {
            "photos": self.photos,
            "owner": self.owner,
            "friends": self.friends,
            "metadata": codec.encode(self.metadata)
        }

    @staticmethod
    def from_dict(data: types.PhotoAlbumDict) -> "Album":
        return Album(
            photos=data["photos"],
            owner=data["owner"],
            friends=data["friends"],
            metadata=codec.decode(data["metadata"])
        )

    def add_photo(self, photo: bytes) -> None:
        """
        adds the given photo blob to the album
        """
        self.photos.append(photo)

    def add_friend(self, friend_pp: types.PublicProfile) -> None:
        """
        Add the given friend to the album
        """
        self.friends[friend_pp["username"]] = friend_pp

    def remove_friend(self, friend_username: str) -> None:
        """
        remove the given friend's permission from the album
        """
        if friend_username in self.friends.keys():
            del self.friends[friend_username]
        if friend_username in self.metadata.keys():
            del self.metadata[friend_username]

    def add_friend_signature(self, friend_name, signature):
        self.metadata[friend_name] = signature

    def veirfy_friends(self, owner_pk):
        for friend_username in self.friends.copy().keys():
            if friend_username not in self.metadata.keys():
                self.remove_friend(friend_username)
            # if it is in the metadata, make sure the signature is verified
            elif not crypto.verify_sign(owner_pk, codec.encode(hash(friend_username)), self.metadata[friend_username]):
                # if signature not verified remove friend
                self.remove_friend(friend_username)


