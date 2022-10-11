#!/usr/bin/env python3

"""
client holds the lab client.
"""

import typing as t
import uuid

from server.reference_server import *
import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors
import requests
from ag.common.mock_http import (
    link_client_server,
)  # imported for doctests, unneeded otherwise


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
        "SynchronizeResponse": types.SynchronizeResponse,
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

        self._photos: t.List[bytes] = []  # list of photos in put_photo order
        self._last_log_number: int = 0
        self._next_photo_id = 0
        self._photo_signatures = dict()
        self._photo_sig_chain = hash(None)
        self._log_sign_chain = hash(None)

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
        # for a REGISTER log entry, we just zero the photo-related field
        # if self._last_log_number != 0:
        #     raise errors.SynchronizationError(None)
        signature = self.sign(types.OperationCode.REGISTER.value, 0)
        log = LogEntry(types.OperationCode.REGISTER, 0, signature)
        req = types.RegisterRequest(
            self._client_id, self._username, self._auth_secret, log.encode()
        )
        # print(f"Registration log: {log}")
        resp = self.send_rpc(req)
        assert isinstance(resp, types.RegisterResponse)
        if resp.error is None:
            self._last_log_number += 1
            # print(f"+=+= current last log: {self._last_log_number}")
            self._server_session_token = resp.token
            self._token_sig = hash(str(signature) + str(resp.token))


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
        req = types.LoginRequest(self._client_id, self._username, self._auth_secret)
        resp = self.send_rpc(req)
        assert isinstance(resp, types.LoginResponse)
        if resp.error is None:
            self._server_session_token = resp.token
        elif resp.error == types.Errcode.LOGIN_FAILED:
            raise errors.LoginFailedError(self._username)
        else:
            raise Exception(resp)

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
        if len(self._photos) != self._next_photo_id:
            raise errors.SynchronizationError(None)
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

    def _fetch_photo(self, photo_id) -> bytes:
        """Get a photo from the server using the unique PhotoID
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
            self._client_id, self._username, self._server_session_token, photo_id
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
        # print("Started PUT operation for ", photo_blob)
        self._synchronize()
        photo_id = self._next_photo_id
        signature = self.sign(types.OperationCode.PUT_PHOTO.value, photo_id, photo_blob)
        log = LogEntry(types.OperationCode.PUT_PHOTO, photo_id, signature)
        req = types.PutPhotoRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            log.encode(),
            photo_blob,
            photo_id,
        )

        resp = self.send_rpc(req)
        assert isinstance(resp, types.PutPhotoResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)

        self._record_new_photo(photo_blob)
        self._last_log_number += 1
        # self.print_data()
        # print(f"END OF Photo PUT\n"
        #       f"photos: {self._photos}\n"
        #       f"total logs: {self._last_log_number}")
        return photo_id

    def _record_new_photo(self, photo_blob):
        """
        Locally record a new photo.
        """
        self._next_photo_id += 1
        self._photos.append(photo_blob)
        signature = self.sign(0, self._next_photo_id-1, photo_blob)
        self._photo_signatures[self._next_photo_id-1] = signature
        self._photo_sig_chain = hash(hash(self._photo_sig_chain) + signature)

    def sign(self, opcode, i, photo_blob=None):
        s = str(self.user_secret) + str(opcode) + str(i)
        if photo_blob is not None:
            s += str(photo_blob.decode('utf-8')) + str(self._photo_sig_chain)
        # print(f"+++++++++\n"
        #       f"secret: {str(self.user_secret)}\n"
        #       f"opcode: {str(opcode)}\n"
        #       f"photo_id: {str(i)}\n"
        #       f"photo_blob: {str(photo_blob)}\n"
        #       f"hash: {hash(s)}\n"
        #       f"+++Created hash++++")
        self._log_sign_chain = hash(hash(s) + hash(str(self._log_sign_chain)))
        return self._log_sign_chain

    def check_log_signature(self, log, photo_blob=None):
        received_hash = log.signature
        s = str(self.user_secret) + str(log.opcode) + str(log.photo_id)
        if photo_blob is not None:
            s += str(photo_blob.decode('utf-8')) + str(self._photo_sig_chain)
        if received_hash == hash(hash(s) + hash(str(self._log_sign_chain))):
            self._log_sign_chain = received_hash
            return True
        return False

    def check_sequence(self, received_id):
        """
        we should only receive updates from the server
        thus if we receive an old id this means we diverged
        :param received_id:
        :return:
        """
        return received_id < self._next_photo_id

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
        # print(f"===last log number==={self._last_log_number}")
        # print(self._photos)
        req = types.SynchronizeRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            self._last_log_number,
        )

        resp = self.send_rpc(req)
        assert isinstance(resp, types.SynchronizeResponse)

        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error == types.Errcode.VERSION_TOO_HIGH:
            raise errors.SynchronizationError(errors.VersionTooHighError())
        elif resp.error is not None:
            raise Exception(resp)
        log_sequence_check = set()
        last_index = self._next_photo_id-1
        logs = []
        for encoded in resp.encoded_log_entries:
            try:
                logs.append(LogEntry.decode(encoded))
            except errors.MalformedEncodingError as e:
                raise errors.SynchronizationError(e)
        for log in logs:
            if log.photo_id:
                if log.photo_id in log_sequence_check:
                    # print("photo id has been seen")
                    raise errors.SynchronizationError(None)
                log_sequence_check.add(log.photo_id)
            if log.opcode not in {1,2}:
                print("op code not corrent")
                raise errors.SynchronizationError(None)
            if log.opcode == types.OperationCode.REGISTER.value:
                if log.photo_id != self._next_photo_id:
                    # if we registered the log id should be the same as next
                    # photo id
                    raise errors.SynchronizationError(None)
                if not self.check_log_signature(log, None):
                    raise errors.SynchronizationError(None)
            if log.opcode == types.OperationCode.PUT_PHOTO.value:
                if log.photo_id != last_index + 1:
                    # print("logs not in sequence")
                    raise errors.SynchronizationError(None)
                last_index += 1
                if log.photo_id <= self._next_photo_id - 1:
                    # print("log received with higher value")
                    raise errors.SynchronizationError(None)
                photo_blob = self._fetch_photo(log.photo_id)
                if not self.check_log_signature(log, photo_blob):
                    # print("wrong signature")
                    raise errors.SynchronizationError(None)
                self._record_new_photo(photo_blob)
            self._last_log_number += 1



class LogEntry:
    def __init__(
        self,
        opcode: types.OperationCode,
        photo_id: int,
        signature
    ) -> None:
        """
        Generates a new log entry. `photo_id` should be 0 for a register entry.
        """
        self.opcode = opcode.value
        self.photo_id = photo_id
        self.signature = signature

    def encode(self) -> bytes:
        return codec.encode(
            [
                self.opcode,
                self.photo_id,
                self.signature
            ]
        )

    def data_hash(self) -> bytes:
        return crypto.data_hash(self.encode())

    def __str__(self):
        return f"opcode: {self.opcode}," \
               f"photo_id: {self.photo_id}," \
               f"signature: {self.signature}"

    @classmethod
    def decode(cls, data: bytes) -> "LogEntry":
        opcode, photo_id, signature = codec.decode(data)
        if opcode not in {1, 2}:
            raise errors.SynchronizationError(None)
        return cls(types.OperationCode(opcode), photo_id, signature)


def log_entry(opcode, photo_id, signature):
    return {
        'opcode':   opcode.value,
        'photo_id': photo_id,
        'signature': signature
    }


