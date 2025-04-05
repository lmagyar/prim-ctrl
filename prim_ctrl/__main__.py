
import argparse
import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from abc import abstractmethod
from contextlib import nullcontext, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import aiohttp
import asyncssh
import dns.asyncresolver
import dns.resolver
import dns.rdatatype
from aiohttp import ClientTimeout, web
from aiohttp.abc import AbstractResolver as DnsResolver, ResolveResult
from platformdirs import user_cache_dir
from tailscale import Device as TailscaleDeviceInfo, Tailscale as TailscaleApi
from zeroconf import Zeroconf, ServiceInfo, ServiceListener as ZeroconfServiceListener
from zeroconf.asyncio import AsyncZeroconf

########

class LevelFormatter(logging.Formatter):
    logging.Formatter.default_msec_format = logging.Formatter.default_msec_format.replace(',', '.') if logging.Formatter.default_msec_format else None

    def __init__(self, fmts: dict[int, str], fmt: str, **kwargs):
        super().__init__()
        self.formatters = dict({level: logging.Formatter(fmt, **kwargs) for level, fmt in fmts.items()})
        self.default_formatter = logging.Formatter(fmt, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters.get(record.levelno, self.default_formatter).format(record)

class Logger(logging.Logger):
    def __init__(self, name, level = logging.NOTSET):
        super().__init__(name, level)
        self.exitcode = 0

    def prepare(self, timestamp: bool, silent: bool):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            LevelFormatter(
                {
                    logging.WARNING: '%(asctime)s %(message)s',
                    logging.INFO: '%(asctime)s %(message)s',
                    logging.DEBUG: '%(asctime)s %(levelname)s %(message)s',
                },
                '%(asctime)s %(name)s: %(levelname)s: %(message)s')
            if timestamp else
            LevelFormatter(
                {
                    logging.WARNING: '%(message)s',
                    logging.INFO: '%(message)s',
                    logging.DEBUG: '%(levelname)s %(message)s',
                },
                '%(name)s: %(levelname)s: %(message)s')
        )
        self.addHandler(handler)
        if self.level == logging.NOTSET:
            self.setLevel(logging.WARNING if silent else logging.INFO)

    def exception_or_error(self, e: Exception):
        if self.level == logging.NOTSET or self.level == logging.DEBUG:
            logger.exception(e)
        else:
            if hasattr(e, '__notes__'):
                logger.error("%s: %s", LazyStr(repr, e), LazyStr(", ".join, e.__notes__))
            else:
                logger.error(LazyStr(repr, e))

    def error(self, msg, *args, **kwargs):
        self.exitcode = 1
        super().error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.exitcode = 1
        super().critical(msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        if level >= logging.ERROR:
            self.exitcode = 1
        super().log(level, msg, *args, **kwargs)

class LazyStr:
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.result = None
    def __str__(self):
        if self.result is None:
            if callable(self.func):
                self.result = str(self.func(*self.args, **self.kwargs))
            else:
                self.result = str(self.func)
        return self.result

logger = Logger(Path(sys.argv[0]).name)

########

class Subprocess:

    # # based on https://stackoverflow.com/a/55656177/2755656
    # @staticmethod
    # def sync_ping(host, packets: int = 1, timeout: float = 1):
    #     if platform.system().lower() == 'windows':
    #         command = ['ping', '-n', str(packets), '-w', str(int(timeout*1000)), host]
    #         # don't use text=True, the async version will raise ValueError("text must be False"), who knows why
    #         result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    #         return result.returncode == 0 and b'TTL=' in result.stdout
    #     else:
    #         command = ['ping', '-c', str(packets), '-W', str(int(timeout)), host]
    #         result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #         return result.returncode == 0

    @staticmethod
    async def ping(host, packets: int = 1, timeout: float = 1):
        if platform.system().lower() == 'windows':
            command = ['ping', '-n', str(packets), '-w', str(int(timeout*1000)), host]
            # don't use text=True, the async version will raise ValueError("text must be False"), who knows why
            proc = await asyncio.create_subprocess_exec(*command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, _stderr = await proc.communicate()
            return proc.returncode == 0 and b'TTL=' in stdout
        else:
            command = ['ping', '-c', str(packets), '-W', str(int(timeout)), host]
            proc = await asyncio.create_subprocess_exec(*command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _stdout, _stderr = await proc.communicate()
            return proc.returncode == 0

    @staticmethod
    async def tailscale(args: list[str]):
        command = ['tailscale']
        command.extend(args)
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        try:
            proc = await asyncio.create_subprocess_exec(*command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=creationflags)
        except FileNotFoundError as e:
            e.add_note(f"Please check that Tailscale is installed properly")
            raise
        stdout, _stderr = await proc.communicate()
        return proc.returncode == 0, stdout

########

# resolve directly at an outside DNS, because local magicDNS will return the tailnet IP
# Note: aiohttp's AsyncResolver can't be used when asyncio.create_subprocess_exec is used
#       aiohttp's AsyncResolver uses aiodns, that needs a SelectorEventLoop on Windows, and that's loop.subprocess_exec is not implemented, but required by asyncio.create_subprocess_exec
class ExternalDnsResolver(DnsResolver):
    EXTERNAL_DNS = '1.1.1.1'

    def __init__(self):
        self.dns_resolver = None
        self.cache = dict[tuple[str, int, socket.AddressFamily], tuple[float, list[ResolveResult]]]()

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_UNSPEC) -> list[ResolveResult]:
        logger.debug("Resolving DNS for %s:%i (%s)", host, port, "ipv6" if family == socket.AF_INET6 else "ipv4")

        key = (host, port, family)
        expiration, hosts = self.cache.get(key, (None, None))
        if expiration and hosts:
            if time.time() < expiration:
                logger.debug(" Found in cache")
                return hosts
            else:
                del self.cache[key]
        # in case of a long-running process, we should regularly delete other expired items also

        try:
            if not self.dns_resolver:
                self.dns_resolver = await dns.asyncresolver.make_resolver_at(ExternalDnsResolver.EXTERNAL_DNS)
            answer = await self.dns_resolver.resolve(host, rdtype=dns.rdatatype.AAAA if family == socket.AF_INET6 else dns.rdatatype.A)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            msg = exc.args[1] if len(exc.args) >= 1 else "DNS lookup failed"
            raise OSError(None, msg) from exc

        hosts = []
        for rr in answer:
            address = rr.to_text()
            logger.debug(" Resolved as: %s", address)
            hosts.append(
                ResolveResult(
                    hostname=host,
                    host=address,
                    port=port,
                    family=family,
                    proto=0,
                    flags=socket.AI_NUMERICHOST,
                )
            )
        if not hosts:
            raise OSError(None, "DNS lookup failed")

        self.cache[key] = (answer.expiration, hosts)
        return hosts

    async def close(self):
        pass

########

class Pingable:
    @abstractmethod
    async def ping(self, availability_hint: bool | None = None) -> bool:
        pass

    def get_class_name(self):
        return self.__qualname__ if hasattr(self, '__qualname__') else self.__class__.__qualname__.rsplit('.', maxsplit=1)[0]

    @staticmethod
    def get_state_name(available: bool):
        return 'up' if available else 'down'

    async def wait_for(self, available: bool, timeout: float):
        logger.debug("Waiting for %s to be %s (timeout is %ds)", LazyStr(self.get_class_name), LazyStr(Pingable.get_state_name, available), int(timeout))
        async with asyncio.timeout(timeout):
            while await self.ping(available) != available:
                await self._sleep_while_wait(available)

    async def _sleep_while_wait(self, available: bool):
        if not available:
            await asyncio.sleep(1)

class Manager:
    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass

class Manageable(Pingable):
    def __init__(self, manager: Manager):
        super().__init__()
        self.manager = manager

    async def _set_state(self, available: bool, repeat: float, timeout: float):
        action_name = LazyStr(lambda: 'Starting' if available else 'Stopping')
        class_name = LazyStr(self.get_class_name)
        available_name = LazyStr(Pingable.get_state_name, available)
        logger.info("%s %s...", action_name, class_name)
        logger.debug("%s %s (repeat after %ds, timeout is %ds)", action_name, class_name, int(repeat), int(timeout))
        try:
            async with asyncio.timeout(timeout):
                while True:
                    try:
                        if available:
                            await self.manager.start()
                        else:
                            await self.manager.stop()
                        await self.wait_for(available, min(repeat, timeout))
                        break
                    except TimeoutError:
                        pass
        except TimeoutError as e:
            e.add_note(f"Can't get {class_name} {available_name} for {timeout} seconds")
            raise
        logger.info("  %s is %s", class_name, available_name)
        return available

    async def test(self):
        available = await self.ping()
        logger.info("%s is %s", LazyStr(self.get_class_name), LazyStr(Pingable.get_state_name, available))
        return available

    async def start(self, repeat: float, timeout: float):
        return await self._set_state(True, repeat, timeout)

    async def stop(self, repeat: float, timeout: float):
        return await self._set_state(False, repeat, timeout)

class Service(Manageable):
    def __init__(self, host: str, port: int, manager: Manager):
        super().__init__(manager)
        self.host = host
        self.port = port

        self._connect_timeout = 2
        self._special_exceptions = ()
        self._special_exceptions_handler : Callable[[Exception], bool] | None = None

    async def _connect(self, host: str, port: int):
        logger.debug(" Connecting with TCP to %s:%d (timeout is %ds)", host, port, self._connect_timeout)
        async with asyncio.timeout(self._connect_timeout):
            _reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()

    async def _ping(self, availability_hint: bool | None = None):
        logger.debug("Pinging %s (%s:%s)", LazyStr(self.get_class_name), str(self.host), str(self.port))
        await self._connect(self.host, self.port)

    async def ping(self, availability_hint: bool | None = None):
        try:
            await self._ping(availability_hint)
            return True
        except (TimeoutError, socket.gaierror, ConnectionRefusedError):
            return False
        except self._special_exceptions as e:
            if availability_hint is None or availability_hint:
                if self._special_exceptions_handler:
                    if self._special_exceptions_handler(e):
                        raise
                    else:
                        return False
                else:
                    logger.debug("  Unexpected ping exception: %s", LazyStr(e))
                    raise
            else:
                return False
        except Exception as e:
            logger.debug("  Unexpected ping exception: %s", LazyStr(e))
            raise

class SshService(Service):
    def __init__(  self, host: str, port: int, host_name: str, keyfile: str, manager: Manager, **kw):
        super().__init__(host=host, port=port, manager=manager, **kw)
        self.host_name = host_name
        self.keyfile = keyfile

        self._connect_timeout = 3
        self._special_exceptions = (asyncssh.misc.HostKeyNotVerifiable, asyncssh.misc.PermissionDenied, asyncssh.misc.DisconnectError)
        def _handle_special_exceptions(e: Exception):
            if isinstance(e, asyncssh.misc.HostKeyNotVerifiable):
                e.add_note("Check your known_hosts file, see the documentation of prim-sync for more details")
            elif isinstance(e, asyncssh.misc.PermissionDenied):
                e.add_note("Check your private SSH key file, see the documentation of prim-sync for more details")
            else:
                return False
            return True
        self._special_exceptions_handler = _handle_special_exceptions

    async def _connect(self, host: str, port: int):
        logger.debug(" Connecting with SSH to %s:%d (timeout is %ds)", host, port, self._connect_timeout)
        def _client_key():
            try:
                return asyncssh.read_private_key(str(Path.home() / ".ssh" / self.keyfile))
            except asyncssh.KeyImportError:
                # if client key is encrypted, do not specify any key, by default asyncssh first will try to use an ssh-agent to find a decrypted key
                # if client key is NOT encrypted, specify it, because asyncssh will try only the default key file names
                # this is the exact opposite of Paramiko, where we can always specify a key, only when it is encrypted will Paramiko try an ssh-agent
                return ()
        async with (
            # by default it will search for the known_hosts in str(Path.home() / ".ssh" / "known_hosts")
            asyncssh.connect(host, port, options=asyncssh.SSHClientConnectionOptions(
                host_key_alias=self.host_name,
                client_keys=_client_key(),
                connect_timeout=self._connect_timeout)) as conn
        ):
            pass

class Device(Manageable):
    def __init__(self, host: str, manager: Manager):
        super().__init__(manager)
        self.host = host

    async def ping(self, availability_hint: bool | None = None):
        logger.debug("Pinging %s (%s)", LazyStr(self.get_class_name), self.host)
        return await Subprocess.ping(self.host, timeout=2)

class StateSerializer:
    BOOL = {False: Pingable.get_state_name(False), True: Pingable.get_state_name(True)}
    INV_BOOL = {v: k for k, v in BOOL.items()}

    @staticmethod
    def dump_value(v):
        return v if not isinstance(v, bool) else StateSerializer.BOOL[v]

    @staticmethod
    def load_value(v):
        return v if v not in StateSerializer.INV_BOOL else StateSerializer.INV_BOOL[v]

    @staticmethod
    def dumps(d: dict):
        return ','.join(f"{k}={StateSerializer.dump_value(v)}" for k, v in d.items())

    @staticmethod
    def loads(s: str):
        try:
            return dict({k: StateSerializer.load_value(v) for k, v in [s.split('=') for s in s.split(',')]})
        except ValueError as e:
            e.add_note("Missing '=' in state")
            raise

class PhoneState:
    WIFI = 'wifi'
    PFTPD = 'pftpd'

    @abstractmethod
    async def get(self, repeat: float, timeout: float) -> dict:
        pass

########

class Secrets:
    DIR_NAME = '.secrets'

    def __init__(self):
        self.secrets_path = Path.home() / Secrets.DIR_NAME

    def get(self, tokenfile: str):
        with open(str(self.secrets_path / tokenfile), 'rt') as file:
            return file.readline().rstrip()

    def set(self, tokenfile: str, token: str):
        self.secrets_path.mkdir(parents=True, exist_ok=True)
        with open(str(self.secrets_path / tokenfile), 'wt') as file:
            file.write(token)

    def get_age(self, tokenfile: str):
        return (datetime.now(timezone.utc) - datetime.fromtimestamp(os.stat(str(self.secrets_path / tokenfile)).st_mtime, timezone.utc)).total_seconds()

class Cache:
    PRIM_SYNC_APP_NAME = 'prim-sync'

    def __init__(self, app_name: str):
        self.cache_path = Path(user_cache_dir(app_name, False))

    def set(self, key: str, value: str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        with open(cache_filename, 'wt') as file:
            file.write(value)

    def get(self, key: str):
        self.cache_path.mkdir(parents=True, exist_ok=True)
        cache_filename = str(self.cache_path / key)
        if os.path.exists(cache_filename) and os.path.isfile(cache_filename):
            with open(cache_filename, 'rt') as file:
                return file.readline().rstrip()
        else:
            return None

########

class ServiceCache:
    def __init__(self, cache: Cache):
        self.cache = cache

    def set(self, service_name: str, host: str, port: int):
        self.cache.set(service_name, '|'.join([host, str(port)]))

    def get(self, service_name: str):
        if cached_value := self.cache.get(service_name):
            cached_value = cached_value.split('|')
            return (cached_value[0], int(cached_value[1]))
        else:
            return (None, None)

class ServiceResolver:
    def __init__(self, zeroconf: AsyncZeroconf, service_type: str):
        self.zeroconf = zeroconf
        self.service_type = service_type

    async def get(self, service_name: str, timeout: float = 3):
        service_info = await self.zeroconf.async_get_service_info(self.service_type, f"{service_name}.{self.service_type}", timeout=int(timeout*1000))
        if not service_info or not service_info.port:
            raise TimeoutError("Unable to resolve zeroconf (DNS-SD) service information")
        return (service_info.parsed_addresses()[0], int(service_info.port))

class ServiceListener:
    @abstractmethod
    def set_service(self, service_name: str, service_info: ServiceInfo):
        pass

    @abstractmethod
    def del_service(self, service_name: str):
        pass

class ServiceBrowser:
    def __init__(self, zeroconf: AsyncZeroconf, service_type: str):
        self.zeroconf = zeroconf
        self.service_type = service_type

    class ServiceListenerWrapper(ZeroconfServiceListener):
        def __init__(self, listener: ServiceListener):
            self.listener = listener

        @staticmethod
        def get_service_name(name: str):
            return name.split('.', maxsplit=1)[0]

        def set_service(self, zc: Zeroconf, type_: str, name: str):
            service_info = ServiceInfo(type_, name)
            if service_info.load_from_cache(zc):
                self.listener.set_service(ServiceBrowser.ServiceListenerWrapper.get_service_name(name), service_info)

        def del_service(self, zc: Zeroconf, type_: str, name: str):
            self.listener.del_service(ServiceBrowser.ServiceListenerWrapper.get_service_name(name))

        def add_service(self, zc: Zeroconf, type_: str, name: str):
            self.set_service(zc, type_, name)

        def remove_service(self, zc: Zeroconf, type_: str, name: str):
            self.del_service(zc, type_, name)

        def update_service(self, zc: Zeroconf, type_: str, name: str):
            self.set_service(zc, type_, name)

    async def add_service_listener(self, listener: ServiceListener):
        await self.zeroconf.async_add_service_listener(self.service_type, ServiceBrowser.ServiceListenerWrapper(listener))

SFTP_SERVICE_TYPE = '_sftp-ssh._tcp.local.'

class SftpServiceResolver(ServiceResolver):
    def __init__(self, zeroconf: AsyncZeroconf):
        super().__init__(zeroconf, SFTP_SERVICE_TYPE)

class SftpServiceBrowser(ServiceBrowser):
    def __init__(self, zeroconf: AsyncZeroconf):
        super().__init__(zeroconf, SFTP_SERVICE_TYPE)

class ZeroconfService(Service):
    def __init__(self, service_name: str, service_cache: ServiceCache, service_resolver: ServiceResolver, manager: Manager, **kw):
        super().__init__(host=None, port=None, manager=manager, **kw) # type: ignore
        self.service_name = service_name
        self.service_cache = service_cache
        self.service_resolver = service_resolver

        self._resolve_timeout = 6

    async def _resolve(self):
        logger.debug(" Resolving %s (timeout is %ds)", self.service_name, self._resolve_timeout)
        return await self.service_resolver.get(self.service_name, self._resolve_timeout)

    async def _ping(self, availability_hint: bool | None = None):
        logger.debug("Pinging %s (%s - %s:%s)", LazyStr(self.get_class_name), self.service_name, str(self.host), str(self.port))
        if self.host and self.port:
            await self._connect(self.host, self.port)
        else:
            host, port = self.service_cache.get(self.service_name)
            if host and port:
                try:
                    await self._connect(host, port)
                    self.host = host
                    self.port = port
                    return
                except (TimeoutError, socket.gaierror, ConnectionRefusedError) + self._special_exceptions as e:
                    if availability_hint is None or availability_hint:
                        logger.debug("  %s", LazyStr(repr, e))
                    else:
                        raise
            host, port = await self._resolve()
            await self._connect(host, port)
            # if resolution is happened through the ServiceListener, cache is already set, but resolution can happen through request/response also
            self.service_cache.set(self.service_name, host, port)
            self.host = host
            self.port = port

class ZeroconfSshService(ZeroconfService, SshService):
    def __init__(self, service_name: str, service_cache: ServiceCache, service_resolver: ServiceResolver, keyfile: str, manager: Manager):
        super().__init__(service_name=service_name, service_cache=service_cache, service_resolver=service_resolver, host_name=service_name, keyfile=keyfile, manager=manager)

########

class Phone:
    def __init__(self, zeroconf_sftp: ZeroconfSshService, vpn: Device | None, remote_sftp: SshService | None, state: PhoneState | None):
        self.zeroconf_sftp = zeroconf_sftp
        self.vpn = vpn
        self.remote_sftp = remote_sftp
        self.state = state

class PftpdServiceListener(ServiceListener):
    def __init__(self, server_name: str, cache: ServiceCache):
        self.server_name = server_name
        self.cache = cache

    def set_service(self, service_name: str, service_info: ServiceInfo):
        if service_name == self.server_name and service_info.port:
            host = service_info.parsed_addresses()[0]
            port = int(service_info.port)
            self.cache.set(service_name, host, port)
            logger.debug(" (ServiceListener) Resolved %s to %s:%d", service_name, host, port)

    def del_service(self, service_name: str):
        pass

class RemotePftpd(SshService):
    def __init__(self, host: str, port: int, host_name: str, keyfile: str, manager: Manager):
        super().__init__(host, port, host_name, keyfile, manager)
        self.__qualname__ = "pFTPd"

class ZeroconfPftpd(ZeroconfSshService):
    def __init__(self, service_name: str, service_cache: ServiceCache, service_resolver: ServiceResolver, keyfile: str, manager: Manager):
        super().__init__(service_name, service_cache, service_resolver, keyfile, manager)
        self.__qualname__ = "pFTPd"

class RemoteTailscale(Device):
    def __init__(self, tailnet: str, machine_name: str, manager: Manager):
        super().__init__(f'{machine_name}.{tailnet}', manager)
        self.tailnet = tailnet
        self.__qualname__ = "Remote Tailscale"

########

class Local:
    def __init__(self, vpn: Manageable | None):
        self.vpn = vpn

class Tailscale():
    TOKEN_SUFFIX = '.token'

    def __init__(self, secrets: Secrets, session: aiohttp.ClientSession, tailnet: str, secretfile: str):
        self.secrets = secrets
        self.session = session
        self.tailnet = tailnet
        self.secretfile = secretfile
        self.tailscale_api = None

    async def _start(self):
        # create new access_token from client_secret if previous access_token is expired or nonexistent
        tokenfile = self.secretfile + Tailscale.TOKEN_SUFFIX
        token = None
        try:
            if 3300 > self.secrets.get_age(tokenfile):
                token = self.secrets.get(tokenfile)
        except FileNotFoundError:
            pass
        if token is None:
            secret = self.secrets.get(self.secretfile)
            client_id = secret.split('-')[2]
            data = {
                "client_id": client_id,
                "client_secret": secret,
                "grant_type": "client_credentials",
                "scope" : "devices:core:read"
            }
            logger.debug("Generating new Tailscale API token")
            async with self.session.post('https://api.tailscale.com/api/v2/oauth/token', data=data) as response:
                json_response = await response.json()
            expires_in = json_response.get('expires_in')
            token = json_response.get('access_token')
            assert expires_in is not None and token is not None
            if expires_in < 3600:
                raise RuntimeError(f'Tailscale access token received shorter that 1 hour, {expires_in} seconds expiration')
            self.secrets.set(tokenfile, token)
        self.tailscale_api = TailscaleApi(session=self.session, request_timeout=30, tailnet=self.tailnet, api_key=token)

    async def device(self, machine_name: str) -> TailscaleDeviceInfo:
        if not self.tailscale_api:
            await self._start()
        assert self.tailscale_api is not None
        logger.debug("Calling Tailscale API for devices")
        devices = await self.tailscale_api.devices()
        name = f"{machine_name}.{self.tailnet}"
        for device in devices.values():
            if device.name == name:
                return device
        raise RuntimeError(f"Device {machine_name} in {self.tailnet} is unknown by Tailscale")

class LocalTailscaleManager(Manager):
    async def start(self):
        if not (await Subprocess.tailscale(['up']))[0]:
            raise RuntimeError("Failed to start up local Tailscale")

    async def stop(self):
        if not (await Subprocess.tailscale(['down']))[0]:
            raise RuntimeError("Failed to shut down local Tailscale")

class LocalTailscale(Manageable):
    def __init__(self, tailscale: Tailscale | None = None, machine_name: str | None = None):
        super().__init__(LocalTailscaleManager())
        self.tailscale = tailscale
        self.machine_name = machine_name
        self.__qualname__ = "Local Tailscale"

    async def ping(self, availability_hint: bool | None = None):
        logger.debug("Getting status of %s", LazyStr(self.get_class_name))
        success, stdout = await Subprocess.tailscale(['status', '--json', '--peers=false', '--self=true'])
        if success:
            status = json.loads(stdout)
        return success and status['BackendState'] == 'Running' and status['Self']['Online']

    async def _sleep_while_wait(self, available: bool):
        await asyncio.sleep(0.250)

    async def start(self, repeat: float, timeout: float):
        if self.tailscale and self.machine_name:
            device_info = await self.tailscale.device(self.machine_name)
        start_result = await super().start(repeat, timeout)
        if start_result and self.tailscale and self.machine_name:
            max_last_seen_age = 7200
            wait_on_fresh_start = 15
            difference = datetime.now(timezone.utc).replace(microsecond=0) - device_info.last_seen if device_info.last_seen else None
            difference_sec = difference.total_seconds() if difference else None
            if difference_sec is None or difference_sec > max_last_seen_age:
                # wait a little to avoid caching empty DNS entry for 5 minutes, better to loose a few seconds than 300s
                logger.debug("Waiting for %is, because %s is freshly started up and wasn't seen for more than %ih (last seen at %s, %s ago)",
                     wait_on_fresh_start, LazyStr(self.get_class_name), max_last_seen_age/3600,
                     LazyStr((lambda last_seen : str(last_seen.astimezone())[:19] if last_seen else None), device_info.last_seen), LazyStr(difference))
                await asyncio.sleep(wait_on_fresh_start)
        return start_result

class Funnel(Pingable):
    LOCAL_HOST = '127.0.0.1'

    def __init__(self, tailnet: str, machine_name: str, local_port: int, local_path: str, external_port: int, dns_resolver: DnsResolver):
        self.machine_name = machine_name
        self.local_port = local_port
        self.external_name = f'{machine_name}.{tailnet}'
        self.external_port = external_port
        self.external_url = f'https://{machine_name}.{tailnet}:{external_port}{local_path}'
        self.dns_resolver = dns_resolver

    async def wait_for(self, available: bool, timeout: float):
        self._sleepcounter = 0
        await super().wait_for(available, timeout)

    async def ping(self, availability_hint: bool | None = None):
        logger.debug("Resolving DNS for %s (%s)", LazyStr(self.get_class_name), self.external_name)
        try:
            _answer = await self.dns_resolver.resolve(self.external_name, self.external_port)
        except Exception:
            return False
        return True

    async def _sleep_while_wait(self, available: bool):
        if 0 != self._sleepcounter and 0 == self._sleepcounter % 6:
            logger.info("Waiting for public DNS records to be updated for %s (%s)...", LazyStr(self.get_class_name), self.external_name)
        await asyncio.sleep(10)
        self._sleepcounter += 1

########

class Webhooks:
    PING_PATH = 'ping'
    VARIABLE_PATH = 'variable'

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.variables = dict[str, asyncio.Queue[str]]()

    @staticmethod
    def get_ping_path():
        return f'/{Webhooks.PING_PATH}'

    @staticmethod
    def get_variable_path(variable: str):
        return f'/{Webhooks.VARIABLE_PATH}/{variable}'

    async def _start(self):
        async def _ping(request: web.Request):
            return web.Response(text='pong')
        async def _receive_variable(request: web.Request):
            queue = self.variables.get(request.match_info['name'])
            if queue:
                with suppress(asyncio.QueueFull):
                    queue.put_nowait(await request.text())
            return web.Response(text='OK')
        app = web.Application()
        app.add_routes([
            web.get(f'/{Webhooks.PING_PATH}', _ping),
            web.post(f'/{Webhooks.VARIABLE_PATH}' + r'/{name}', _receive_variable)])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, host=self.host, port=self.port)
        await self.site.start()

    async def _stop(self):
        await self.runner.cleanup()

    def subscribe_variable(self, variable: str):
        if variable not in self.variables:
            self.variables[variable] = asyncio.Queue[str](maxsize=16)

    def unsubscribe_variable(self, variable: str):
        self.variables.pop(variable)

    async def get_variable(self, variable: str, timeout: float):
        queue = self.variables.get(variable)
        if not queue:
            raise ValueError(f"The {variable} is unknown")
        try:
            async with asyncio.timeout(timeout):
                return await queue.get()
        except TimeoutError as e:
            e.add_note(f"Can't get value of {variable} for {timeout} seconds")
            raise

    def __enter__(self):
        raise TypeError("Use async with instead")
    def __exit__(self, exc_type, exc_value, exc_tb):
        pass
    async def __aenter__(self):
        await self._start()
        return self
    async def __aexit__(self, exc_type, exc_value, exc_tb):
        await self._stop()

class Automate:
    def __init__(self, secrets: Secrets, session: aiohttp.ClientSession, account: str, device: str, tokenfile: str):
        self.session = session
        self.account = account
        self.device = device
        self.secret = secrets.get(tokenfile)

    async def send_message(self, message: str):
        data = {
            "secret": self.secret,
            "to": self.account,
            "device": self.device,
            "priority": "high",
            "payload": f"prim-ctrl;{time.time()};" + message
        }
        logger.debug("Messaging Automate with: %s", message)
        async with self.session.post(f'https://llamalab.com/automate/cloud/message', json=data) as response:
            await response.text()

class AutomatePftpdManager(Manager):
    def __init__(self, automate: Automate):
        self.automate = automate

    async def start(self):
        await self.automate.send_message('start-pftpd')

    async def stop(self):
        await self.automate.send_message('stop-pftpd')

class AutomateTailscaleManager(Manager):
    def __init__(self, automate: Automate):
        self.automate = automate

    async def start(self):
        await self.automate.send_message('start-tailscale')

    async def stop(self):
        await self.automate.send_message('stop-tailscale')

class WebhookPing(Pingable):
    def __init__(self, session: aiohttp.ClientSession, webhooks: Webhooks, funnel: Funnel):
        self.session = session
        self.webhooks = webhooks
        self.funnel = funnel
        self.ping_url = f'{self.funnel.external_url}{Webhooks.get_ping_path()}'
        self.__qualname__ = "Webhooks"

    async def ping(self, availability_hint: bool | None = None):
        logger.debug("Calling url %s", self.ping_url)
        try:
            async with self.session.get(self.ping_url, timeout=ClientTimeout(total=1)) as response:
                return 'pong' == await response.text()
        except Exception:
            return False

    async def _sleep_while_wait(self, available: bool):
        await asyncio.sleep(1)

class AutomatePhoneState(PhoneState):
    VARIABLE_STATE = 'state'

    def __init__(self, general_session: aiohttp.ClientSession, external_dns_session: aiohttp.ClientSession, webhooks: Webhooks, automate: Automate, funnel: Funnel):
        self.webhooks = webhooks
        self.automate = automate
        self.funnel = funnel
        self.local_webhook_ping = WebhookPing(general_session, webhooks, funnel)
        self.external_webhook_ping = WebhookPing(external_dns_session, webhooks, funnel)

    async def get(self, repeat: float, timeout: float):
        logger.info("Getting Phone state...")

        # test funnel + webhooks availability, to not wait for a reply if funnel isn't configured properly
        # though it will be routed locally, it will not go out to Tailscale's TCP forwarder servers, so the route is different from what Automate will see
        test_timeout = 30.0
        logger.debug("Testing Funnel with calling local webhook (timeout is %ds)", int(test_timeout))
        try:
            await self.local_webhook_ping.wait_for(True, test_timeout)
        except Exception as e:
            raise RuntimeError(f"Local Funnel is not configured properly for {self.funnel.external_url}") from e

        # test funnel's DNS resolvability, if local Tailscale is freshly started up after longer down state, it can take up to 10 minutes for public DNS records to get updated
        test_timeout = 600.0
        logger.debug("Testing Funnel's DNS configuration (timeout is %ds)", int(test_timeout))
        try:
            await self.funnel.wait_for(True, test_timeout)
        except Exception as e:
            raise RuntimeError(f"Funnel's DNS is not configured by Tailscale for {self.funnel.external_name}") from e

        # test external funnel + webhooks availability, ie. test funnel tcp forwarders
        # it will NOT be routed locally, so the route is equivalent with / similar to what Automate will see
        test_timeout = 90.0
        logger.debug("Testing Funnel with calling external webhook (timeout is %ds)", int(test_timeout))
        try:
            await self.external_webhook_ping.wait_for(True, test_timeout)
        except Exception as e:
            raise RuntimeError(f"Funnel TCP forwarders are not configured by Tailscale for {self.funnel.external_name}") from e

        # get state
        logger.debug("Getting Phone state (repeat after %ds, timeout is %ds)", int(repeat), int(timeout))
        self.webhooks.subscribe_variable(AutomatePhoneState.VARIABLE_STATE)
        try:
            async with asyncio.timeout(timeout):
                while True:
                    try:
                        await self.automate.send_message(f'get-state;{self.funnel.external_url}{Webhooks.get_variable_path(AutomatePhoneState.VARIABLE_STATE)}')
                        state = await self.webhooks.get_variable(AutomatePhoneState.VARIABLE_STATE, min(repeat, timeout))
                        break
                    except TimeoutError:
                        pass
        except TimeoutError as e:
            e.add_note(f"Can't get value of {AutomatePhoneState.VARIABLE_STATE} for {timeout} seconds - please check on your phone in the Automate app, that the prim-ctrl flow is running")
            raise
        finally:
            self.webhooks.unsubscribe_variable(AutomatePhoneState.VARIABLE_STATE)

        logger.info("Phone state is %s", state)
        return StateSerializer.loads(state)

########

class WideHelpFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 35, width: int | None = None) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

async def gather_with_taskgroup(*coros):
    try:
        async with asyncio.TaskGroup() as tg:
            tasks = [tg.create_task(coro) for coro in coros]
        return tuple([task.result() for task in tasks])
    except ExceptionGroup as eg:
        raise eg.exceptions[0] from (None if len(eg.exceptions) == 1 else eg)

class Control:
    PHONE_WIFI = 'remote-wifi'
    LOCAL_VPN = 'local-vpn'
    PHONE_VPN = 'remote-vpn'
    PHONE_SFTP = 'remote-sftp'
    CONNECTED = 'connected'
    ZEROCONF = 'local'
    REMOTE = 'remote'

    @staticmethod
    def setup_parser_arguments(parser):
        parser.add_argument('server_name', metavar='server-name', help="the Servername configuration option from Primitive FTPd app")
        parser.add_argument('keyfile', help="private SSH key filename located under your .ssh folder, see the documentation of prim-sync for more details")
        parser.add_argument('-i', '--intent', choices=["test", "start", "stop"], help="what to do with the apps, default: test", default="test")

    @staticmethod
    def setup_parser_options(parser):
        pass

    @staticmethod
    def setup_parser_groups(parser):
        logging_group = parser.add_argument_group('logging')
        logging_group.add_argument('-t', '--timestamp', help="prefix each message with an UTC timestamp", default=False, action='store_true')
        logging_group.add_argument('-s', '--silent', help="only errors printed", default=False, action='store_true')
        logging_group.add_argument('--debug', help="use debug level logging and add stack trace for exceptions, disables the --silent and enables the --timestamp options", default=False, action='store_true')

    @staticmethod
    def setup_parser_vpngroup(vpn_group):
        vpn_group.add_argument('-ac', '--accept-cellular', help="in case of start, if WiFi is not connected, don't return error, but start VPN up", default=False, action='store_true')
        vpn_group.add_argument('-b', '--backup-state', help="in case of start, backup current state to stdout as single string (in case of an error, it will try to restore the original state but will not write it to stdout)", default=False, action='store_true')
        vpn_group.add_argument('-r', '--restore-state', metavar="STATE", help="in case of stop, restore previous state from STATE (use -b to get a valid STATE string)", action='store')

    @abstractmethod
    async def run(self, args):
        pass

    def prepare(self, args):
        if args.debug:
            logger.setLevel(logging.DEBUG)
        logger.prepare(args.timestamp or args.debug, args.silent)

        if args.accept_cellular and args.intent != 'start':
            raise ValueError("The --accept-cellular options can be enabled only for the start intent")
        if args.backup_state and args.intent != 'start':
            raise ValueError("The --backup-state option can be enabled only for the start intent")
        if args.restore_state and args.intent != 'stop':
            raise ValueError("The --restore-state option can be enabled only for the stop intent")

    async def execute(self, args, local: Local, phone: Phone):
        async def _stop(restore_state: dict | None, stop_only_started: bool = False):
            async def _suppress(coro, default: bool):
                try:
                    return await coro
                except:
                    return default
            if local.vpn and phone.vpn and phone.remote_sftp and await _suppress(local.vpn.test(), True) and await _suppress(phone.vpn.test(), True):
                if (restore_state is None or not restore_state.get(Control.PHONE_SFTP, stop_only_started)) and await _suppress(phone.remote_sftp.test(), True):
                    try:
                        await phone.remote_sftp.stop(10, 30)
                    except Exception as e:
                        logger.exception_or_error(e)
                if restore_state is None or not restore_state.get(Control.PHONE_VPN, stop_only_started):
                    try:
                        await phone.vpn.stop(10, 60)
                    except Exception as e:
                        logger.exception_or_error(e)
            else:
                if (restore_state is None or not restore_state.get(Control.PHONE_SFTP, stop_only_started)):
                    try:
                        await phone.zeroconf_sftp.stop(10, 30)
                    except Exception as e:
                        logger.exception_or_error(e)
            if local.vpn:
                if restore_state is None or not restore_state.get(Control.LOCAL_VPN, stop_only_started):
                    try:
                        await local.vpn.stop(10, 30)
                    except Exception as e:
                        logger.exception_or_error(e)
        match args.intent:
            case 'test':
                if local.vpn and phone.vpn and phone.remote_sftp and phone.state:
                    if await local.vpn.test():
                        phone_state, _vpn_state = await gather_with_taskgroup(phone.state.get(10, 30), phone.vpn.test())
                elif local.vpn and phone.vpn and phone.remote_sftp and await local.vpn.test() and await phone.vpn.test():
                    await phone.remote_sftp.test()
                else:
                    await phone.zeroconf_sftp.test()
            case 'start':
                if local.vpn and phone.vpn and phone.remote_sftp:
                    state = dict()
                    try:
                        # gather local state info
                        local_vpn_state = await local.vpn.test()
                        state[Control.LOCAL_VPN] = local_vpn_state

                        # start changing local state - we need a local vpn to be able to access the state of the remote vpn and optionally the phone
                        if not state[Control.LOCAL_VPN]:
                            await local.vpn.start(10, 30)

                        zeroconf_accessible = False
                        remote_accessible = False

                        # gather phone state info
                        if phone.state:
                            phone_state, phone_vpn_state = await gather_with_taskgroup(phone.state.get(10, 30), phone.vpn.test())
                            state[Control.PHONE_WIFI] = phone_state[PhoneState.WIFI]
                            state[Control.PHONE_VPN] = phone_vpn_state
                            state[Control.PHONE_SFTP] = phone_state[PhoneState.PFTPD]
                            if not state[Control.PHONE_WIFI] and not args.accept_cellular:
                                raise RuntimeError(f"Phone is not on Wi-Fi network")
                        else:
                            state[Control.PHONE_VPN] = await phone.vpn.test()
                            if state[Control.PHONE_VPN]:
                                state[Control.PHONE_SFTP] = remote_accessible = await phone.remote_sftp.test()

                        # start changing phone state
                        if phone.state:
                            if not state[Control.PHONE_SFTP]:
                                if not state[Control.PHONE_VPN]:
                                    if state[Control.PHONE_WIFI]:
                                        try:
                                            zeroconf_accessible = await phone.zeroconf_sftp.start(10, 30)
                                        except TimeoutError:
                                            await phone.vpn.start(10, 60)
                                            remote_accessible = await phone.remote_sftp.test()
                                    else:
                                        await phone.vpn.start(10, 60)
                                        remote_accessible = await phone.remote_sftp.start(10, 30)
                                else:
                                    remote_accessible = await phone.remote_sftp.start(10, 30)
                                    if state[Control.PHONE_WIFI]:
                                        zeroconf_accessible = await phone.zeroconf_sftp.test()
                            else:
                                if not state[Control.PHONE_VPN]:
                                    if not state[Control.PHONE_WIFI] or not (zeroconf_accessible := await phone.zeroconf_sftp.test()):
                                        await phone.vpn.start(10, 60)
                                        remote_accessible = await phone.remote_sftp.test()
                                else:
                                    zeroconf_accessible, remote_accessible = await gather_with_taskgroup(phone.zeroconf_sftp.test(), phone.remote_sftp.test())
                        else:
                            if not state[Control.PHONE_VPN]:
                                if not (zeroconf_accessible := await phone.zeroconf_sftp.test()):
                                    try:
                                        zeroconf_accessible = await phone.zeroconf_sftp.start(10, 30)
                                    except TimeoutError:
                                        await phone.vpn.start(10, 60)
                                        remote_accessible = await phone.remote_sftp.test()
                            else:
                                if not state[Control.PHONE_SFTP]:
                                    remote_accessible = await phone.remote_sftp.start(10, 30)
                                zeroconf_accessible = await phone.zeroconf_sftp.test()
                        if not zeroconf_accessible and not remote_accessible:
                            raise RuntimeError(f"Even when {phone.vpn.get_class_name()} and {phone.remote_sftp.get_class_name()} is started, {phone.remote_sftp.get_class_name()} is still not accessible")

                        # print out result on stdout
                        if not args.backup_state:
                            state = dict()
                        state[Control.CONNECTED] = Control.ZEROCONF if zeroconf_accessible else Control.REMOTE
                        print(StateSerializer.dumps(state))
                    except Exception:
                        try:
                            await _stop(state, stop_only_started = True)
                        except Exception as e:
                            logger.exception_or_error(e)
                        raise
                else:
                    try:
                        if not await phone.zeroconf_sftp.test():
                            await phone.zeroconf_sftp.start(10, 30)
                    except Exception:
                        await _stop(None)
                        raise
            case 'stop':
                await _stop(StateSerializer.loads(args.restore_state) if args.restore_state else None)

class AutomateControl(Control):
    @staticmethod
    def setup_subparser(subparsers):
        parser = subparsers.add_parser('Automate', aliases=['a'],
            description="Remote control of your phone's Primitive FTPd and optionally Tailscale app statuses via the Automate app, for more details see https://github.com/lmagyar/prim-ctrl\n\n"
                "Note: you must install Automate app on your phone, download prim-ctrl flow into it, and configure your Google account in the flow to receive messages (see the project's GitHub page for more details)\n"
                "Note: optionally if your phone is not accessible on local network but your laptop and phone is part of the Tailscale VPN then Tailscale VPN can be started on the phone\n"
                "Note: optionally if your laptop is accessible through Tailscale Funnel then VPN on cellular can be refused and app statuses on the phone can be backed up and restored\n\n"
                "Output: even when -b option is not used, the script will output 'connected=(local|remote)', what you can use to determine whether to use -a option for the prim-sync script",
            formatter_class=WideHelpFormatter)

        parser.add_argument('automate_account', metavar='automate-account', help="your Google account email you set up in the Automate flow's 2nd block's (Set variable google_account to...) Value field")
        parser.add_argument('automate_device', metavar='automate-device', help="the device name you can see at the Automate flow's Cloud receive block's This device field")
        parser.add_argument('automate_tokenfile', metavar='automate-tokenfile', help="filename containing Automates's Secret that located under your .secrets folder\n"
            "(generated on https://llamalab.com/automate/cloud, use the same Google account you set the automate_account option to)\n"
            "Note: if the account you use to send messages is different from the automate_account option,\n"
            "set it up in the Automate flow's 3rd block's (Set variable other_managing_accounts to...) Value field")

        Control.setup_parser_arguments(parser)

        Control.setup_parser_options(parser)

        Control.setup_parser_groups(parser)

        vpn_group = parser.add_argument_group('VPN',
            description="To use --tailscale option you must install Tailscale and configure Tailscale VPN on your phone and your laptop\n"
                "To use --funnel option you must configure Tailscale Funnel on your laptop for prim-ctrl's local webhook to accept responses from the Automate app\n"
                "   (eg.: tailscale funnel --bg --https=8443 --set-path=/prim-ctrl \"http://127.0.0.1:12345\")\n"
                "Note: --funnel, --backup-state and --restore-state options can be used only when --tailscale is used\n"
                "Note: --backup-state is accurate only, when --funnel is used\n"
                "Note: --accept-cellular option can be used only when --funnel is used")
        vpn_group.add_argument('--tailscale', nargs=3, metavar=('tailnet', 'remote-machine-name', 'sftp-port'), help=
            "tailnet:             your Tailscale tailnet name (eg. tailxxxx.ts.net)\n"
            "remote-machine-name: your phone's name within your tailnet (just the name, without the tailnet)\n"
            "sftp-port:           Primitive FTPd's sftp port")
        vpn_group.add_argument('--funnel', nargs=5, metavar=('local-machine-name', 'local-port', 'local-path', 'external-port', 'secretfile'), help=
            "local-machine-name:  your laptop's name within your tailnet (just the name, without the tailnet)\n"
            "local-port:          12345 - if you used the example tailscale funnel command above (the local webhook will be started on this port)\n"
            "local-path:          /prim-ctrl - if you used the example tailscale funnel command above\n"
            "external-port:       8443 - if you used the example tailscale funnel command above\n"
            "secretfile:          filename containing Tailscale's Client secret (not API access token, not Auth key) that located under your .secrets folder\n"
            "                     (generated on https://login.tailscale.com/admin/settings/oauth, with 'devices:core:read' scope,\n"
            "                     save only the Client secret in the file, the Client ID is part of it)")
        Control.setup_parser_vpngroup(vpn_group)

        parser.set_defaults(ctor=AutomateControl)

    def prepare(self, args):
        super().prepare(args)
        if args.funnel and not args.tailscale:
            raise ValueError("--funnel option can be used only when --tailscale is used")
        if args.backup_state and not args.tailscale:
            raise ValueError("--backup-state option can be used only when --tailscale is used")
        if args.restore_state and not args.tailscale:
            raise ValueError("--restore-state option can be used only when --tailscale is used")
        if args.accept_cellular and not args.funnel:
            raise ValueError("--accept-cellular option can be used only when --funnel is used")

    async def run(self, args):
        self.prepare(args)

        external_dns_resolver = ExternalDnsResolver()
        async with (
            aiohttp.ClientSession() as general_session,
            aiohttp.ClientSession(
                # Automate messaging server prefers closing connections
                connector=aiohttp.TCPConnector(force_close=True)) as force_close_session,
            aiohttp.ClientSession(
                # Uses external DNS to access Funnet TCP forwarder servers instead of local MagicDNS route
                connector=aiohttp.TCPConnector(resolver=external_dns_resolver)) as external_dns_session,
            AsyncZeroconf() as zeroconf
        ):
            service_cache = ServiceCache(Cache(Cache.PRIM_SYNC_APP_NAME))
            service_resolver = SftpServiceResolver(zeroconf)

            service_listener = PftpdServiceListener(args.server_name, service_cache)
            service_browser = SftpServiceBrowser(zeroconf)
            await service_browser.add_service_listener(service_listener)

            secrets = Secrets()
            automate = Automate(secrets, force_close_session, args.automate_account, args.automate_device, args.automate_tokenfile)
            remote_tailscale = RemoteTailscale(args.tailscale[0], args.tailscale[1], AutomateTailscaleManager(automate)) if args.tailscale else None
            pftpd_manager = AutomatePftpdManager(automate)
            zeroconf_pftpd = ZeroconfPftpd(args.server_name, service_cache, service_resolver, args.keyfile, pftpd_manager)
            remote_pftpd = RemotePftpd(remote_tailscale.host, int(args.tailscale[2]), args.server_name, args.keyfile, pftpd_manager) if remote_tailscale else None
            funnel = Funnel(remote_tailscale.tailnet, args.funnel[0], int(args.funnel[1]), args.funnel[2], int(args.funnel[3]), external_dns_resolver) if remote_tailscale and args.funnel else None
            local_tailscale = (
                LocalTailscale(Tailscale(secrets, general_session, remote_tailscale.tailnet, args.funnel[4]), funnel.machine_name) if remote_tailscale and funnel else
                LocalTailscale() if args.tailscale else
                None)

            async with Webhooks(Funnel.LOCAL_HOST, funnel.local_port) if funnel else nullcontext() as webhooks:
                local = Local(local_tailscale)
                automate_phone_state = AutomatePhoneState(general_session, external_dns_session, webhooks, automate, funnel) if funnel and webhooks else None
                phone = Phone(zeroconf_pftpd, remote_tailscale, remote_pftpd, automate_phone_state)
                await self.execute(args, local, phone)

async def main():
    args = None
    try:
        parser = argparse.ArgumentParser(
            description="Remote control of your phone's Primitive FTPd and optionally Tailscale app statuses via the Automate app, for more details see https://github.com/lmagyar/prim-ctrl",
            formatter_class=WideHelpFormatter)
        subparsers = parser.add_subparsers(required=True,
            title="Phone app to use for control")

        AutomateControl.setup_subparser(subparsers)

        args = parser.parse_args()
        await args.ctor().run(args)

    except Exception as e:
        logger.exception_or_error(e)

    return logger.exitcode

def run():
    with suppress(KeyboardInterrupt):
        exit(asyncio.run(main()))
