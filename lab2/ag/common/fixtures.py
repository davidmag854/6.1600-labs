import typing as t
from common.errors import SynchronizationError

from server.reference_server import InMemoryStorage, ReferenceServer
from server.spec import Server
import common.types as types
import common.errors as errors
from ag.common.testing import test_case
from ag.common.mock_http import link_client_server

from client import client


def new_client(server: Server, username: str) -> client.Client:
    c = client.Client(username)
    link_client_server(c, server)
    return c


def new_device(server: Server, from_client: client.Client) -> client.Client:
    """
    Returns a new Client corresponding to a new device for the given user.

    Note that the client is not yet authorized to the user's account.
    """
    username = from_client.username
    user_secret = from_client.user_secret
    c = client.Client(username, user_secret=user_secret)
    link_client_server(c, server)
    return c


def new_authorized_device(server: Server, from_client: client.Client) -> client.Client:
    """
    Creates _and authorizes_ a new device to the given user's account.

    Returns the (logged in) client
    """
    d = new_device(server, from_client)
    from_client.login()
    from_client.invite_device(d.public_key)
    d.login()
    d.accept_invite(from_client.public_key)
    return d


def two_clients(server: Server) -> t.Tuple[client.Client, client.Client]:
    """
    Creates two clients "alice" and "bob", registers them with the given server,
    and posts one photo from each.

    Returns the two clients
    """

    alice = client.Client("alice")
    link_client_server(alice, server)
    bob = client.Client("bob")
    link_client_server(bob, server)
    # alice posts a photo
    alice.register()
    alice.login()
    alice.put_photo(b"alice_photo_0")
    # bob posts a photo
    bob.register()
    bob.login()
    bob.put_photo(b"bob_photo_0")

    return alice, bob

