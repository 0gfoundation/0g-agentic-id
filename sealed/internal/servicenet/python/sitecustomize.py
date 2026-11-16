"""Network adapter for hosted Python service processes, part of sealed.

sealed puts this directory first on PYTHONPATH of every Python service process,
so Python imports this module at startup (not under -S, -I or -E).

A service process has no network of its own: sealed's confinement allows only
AF_UNIX sockets. Public APIs are reached only through sealed's egress proxy
(HTTP CONNECT on the Unix socket $SEAL_EGRESS_SOCKET, to the manifest's hosts
only) and the model only through sealed's model proxy (plain HTTP on the Unix
socket $SEAL_MODEL_SOCKET, addressed as host ``seal-model``). This module sends
the usual ways of opening a TCP connection to those sockets:
socket.create_connection (urllib, http.client, smtplib, httpx), urllib3's
create_connection (requests), asyncio's loop.create_connection (asyncio
streams, httpx's async client, websockets) and aiohappyeyeballs (aiohttp).
Host names are resolved by the proxy: getaddrinfo hands a name back unchanged.
A client that creates its own TCP socket has no route. It is not a security
boundary: whatever a program does, the kernel lets it open nothing but Unix
sockets.
"""

import errno
import os
import socket
import sys

_EGRESS = os.environ.get("SEAL_EGRESS_SOCKET")
_MODEL = os.environ.get("SEAL_MODEL_SOCKET")
_MODEL_HOST = "seal-model"
_MAX_HEAD = 8192
_DEFAULT = socket._GLOBAL_DEFAULT_TIMEOUT
_PORTS = {"http": 80, "https": 443}


class _Stream(socket.socket):
    """A Unix stream socket standing in for a TCP connection. TCP options
    (TCP_NODELAY, keepalive tuning) do not apply to it and are ignored."""

    __slots__ = ()

    def setsockopt(self, level, *args):
        if level == socket.IPPROTO_TCP:
            return None
        return super().setsockopt(level, *args)


def _route(host, port):
    """Returns (socket path, CONNECT request or None, authority)."""
    if isinstance(host, bytes):
        host = host.decode("ascii")
    host = host.strip("[]")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        host = host.encode("idna").decode("ascii")
    port = int(port)
    authority = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
    if host == _MODEL_HOST:
        if not _MODEL:
            raise OSError(errno.ENETUNREACH, "No model route for this service program")
        if port == 443:
            raise OSError(errno.EPROTONOSUPPORT, "The model route speaks plain HTTP")
        return _MODEL, None, authority
    if not _EGRESS:
        raise OSError(errno.ENETUNREACH, "No network route for this service program")
    request = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (authority, authority)
    return _EGRESS, request.encode("ascii"), authority


def _check(head, authority):
    parts = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    status = parts[1] if len(parts) > 1 else ""
    if status != "200":
        raise ConnectionRefusedError(
            errno.ECONNREFUSED, "Egress proxy refused %s (HTTP %s)" % (authority, status))


def _closed():
    return ConnectionResetError(errno.ECONNRESET, "Egress proxy closed the connection")


def _too_long():
    return ConnectionResetError(errno.ECONNRESET, "Egress proxy response head too long")


def _open(host, port, timeout=_DEFAULT):
    """Opens a blocking stream to host:port through sealed. The proxy's answer
    is read a byte at a time so nothing past it is taken from the stream."""
    path, request, authority = _route(host, port)
    sock = _Stream(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if timeout is not _DEFAULT:
            sock.settimeout(timeout)
        sock.connect(path)
        if request:
            sock.sendall(request)
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                byte = sock.recv(1)
                if not byte:
                    raise _closed()
                head += byte
                if len(head) > _MAX_HEAD:
                    raise _too_long()
            _check(head, authority)
        return sock
    except BaseException:
        sock.close()
        raise


async def _open_async(loop, host, port):
    path, request, authority = _route(host, port)
    sock = _Stream(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, path)
        if request:
            await loop.sock_sendall(sock, request)
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                byte = await loop.sock_recv(sock, 1)
                if not byte:
                    raise _closed()
                head += byte
                if len(head) > _MAX_HEAD:
                    raise _too_long()
            _check(head, authority)
        return sock
    except BaseException:
        sock.close()
        raise


def create_connection(address, timeout=_DEFAULT, source_address=None, *args, **kwargs):
    return _open(address[0], address[1], timeout)


_getaddrinfo = socket.getaddrinfo


def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Literal addresses resolve as usual; a host name comes back unchanged,
    for the proxy to resolve."""
    try:
        return _getaddrinfo(host, port, family, type, proto, flags | socket.AI_NUMERICHOST)
    except socket.gaierror:
        if host is None or flags & socket.AI_NUMERICHOST or type not in (0, socket.SOCK_STREAM):
            raise
    if isinstance(host, bytes):
        host = host.decode("ascii")
    if isinstance(port, bytes):
        port = port.decode("ascii")
    if port is None:
        port = 0
    elif isinstance(port, str):
        if port.isdigit():
            port = int(port)
        elif port in _PORTS:
            port = _PORTS[port]
        else:
            raise socket.gaierror(socket.EAI_SERVICE, "Servname not supported for ai_socktype")
    if family == socket.AF_INET6 or ":" in host:
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port, 0, 0))]
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))]


def _patch_asyncio(module):
    original = module.BaseEventLoop.create_connection

    async def create_connection(self, protocol_factory, host=None, port=None, *,
                                ssl=None, sock=None, server_hostname=None, **kwargs):
        if sock is not None or host is None:
            return await original(self, protocol_factory, host, port, ssl=ssl, sock=sock,
                                  server_hostname=server_hostname, **kwargs)
        sock = await _open_async(self, host, port)
        if ssl and server_hostname is None:
            server_hostname = host
        for key in ("family", "proto", "flags", "local_addr", "happy_eyeballs_delay",
                    "interleave", "all_errors"):
            kwargs.pop(key, None)
        try:
            return await original(self, protocol_factory, ssl=ssl, sock=sock,
                                  server_hostname=server_hostname, **kwargs)
        except BaseException:
            sock.close()
            raise

    module.BaseEventLoop.create_connection = create_connection


def _timeout(value):
    # urllib3 marks "no timeout given" with its own sentinel.
    return value if value is None or isinstance(value, (int, float)) else _DEFAULT


def _patch_urllib3(module):
    def create_connection(address, timeout=_DEFAULT, source_address=None, socket_options=None):
        return _open(address[0], address[1], _timeout(timeout))

    module.create_connection = create_connection


def _patch_aiohappyeyeballs(module):
    async def start_connection(addr_infos, *, loop=None, **kwargs):
        if loop is None:
            import asyncio
            loop = asyncio.get_running_loop()
        error = OSError(errno.EHOSTUNREACH, "No address to connect to")
        for info in addr_infos:
            try:
                return await _open_async(loop, info[4][0], info[4][1])
            except OSError as e:
                error = e
        raise error

    module.start_connection = start_connection


_PATCHES = {
    "asyncio.base_events": _patch_asyncio,
    "urllib3.util.connection": _patch_urllib3,
    "aiohappyeyeballs": _patch_aiohappyeyeballs,
}


class _Patched:
    """Runs a module's loader, then patches the module."""

    def __init__(self, loader, patch):
        self._loader, self._patch = loader, patch

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        self._patch(module)

    def __getattr__(self, name):
        return getattr(self._loader, name)


class _AfterImport:
    """Patches the modules in _PATCHES as they are imported."""

    def find_spec(self, name, path=None, target=None):
        patch = _PATCHES.get(name)
        if patch is None:
            return None
        for finder in sys.meta_path:
            find = getattr(finder, "find_spec", None)
            if finder is self or find is None:
                continue
            spec = find(name, path, target)
            if spec is not None:
                if spec.loader is not None:
                    spec.loader = _Patched(spec.loader, patch)
                return spec
        return None


socket.create_connection = create_connection
socket.getaddrinfo = getaddrinfo
for _name, _patch in _PATCHES.items():
    if _name in sys.modules:
        _patch(sys.modules[_name])
sys.meta_path.insert(0, _AfterImport())
if _MODEL:
    os.environ["SEAL_MODEL_URL"] = "http://%s/model" % _MODEL_HOST
