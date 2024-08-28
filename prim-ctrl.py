
import argparse
import asyncio
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
from typing import Dict

import aiohttp
from aiohttp import web
from platformdirs import user_cache_dir
from zeroconf import Zeroconf, ServiceInfo, ServiceListener as ZeroconfServiceListener
from zeroconf.asyncio import AsyncZeroconf

########

class LevelFormatter(logging.Formatter):
    logging.Formatter.default_msec_format = logging.Formatter.default_msec_format.replace(',', '.') if logging.Formatter.default_msec_format else None

    def __init__(self, fmts: Dict[int, str], fmt: str, **kwargs):
        super().__init__()
        self.formatters = dict({level: logging.Formatter(fmt, **kwargs) for level, fmt in fmts.items()})
        self.default_formatter = logging.Formatter(fmt, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters.get(record.levelno, self.default_formatter).format(record)

class Logger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
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
            self.result = str(self.func(*self.args, **self.kwargs))
        return self.result

logger = Logger(Path(sys.argv[0]).name)

########

# based on https://stackoverflow.com/a/55656177/2755656
def sync_ping(host, packets: int = 1, timeout: float = 1):
    if platform.system().lower() == 'windows':
        command = ['ping', '-n', str(packets), '-w', str(int(timeout*1000)), host]
        result = subprocess.run(command, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return result.returncode == 0 and b'TTL=' in result.stdout
    else:
        command = ['ping', '-c', str(packets), '-W', str(int(timeout)), host]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

async def async_ping(host, packets: int = 1, timeout: float = 1):
    if platform.system().lower() == 'windows':
        command = ['ping', '-n', str(packets), '-w', str(int(timeout*1000)), host]
        proc = await asyncio.create_subprocess_exec(*command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        stdout, _stderr = await proc.communicate()
        return proc.returncode == 0 and b'TTL=' in stdout
    else:
        command = ['ping', '-c', str(packets), '-W', str(int(timeout)), host]
        proc = await asyncio.create_subprocess_exec(*command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _stdout, _stderr = await proc.communicate()
        return proc.returncode == 0

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

    async def test(self):
        available = await self.ping()
        logger.info("%s is %s", LazyStr(self.get_class_name), LazyStr(Pingable.get_state_name, available))
        return available

    async def start(self, repeat: float, timeout: float):
        await self._set_state(True, repeat, timeout)

    async def stop(self, repeat: float, timeout: float):
        await self._set_state(False, repeat, timeout)

class Service(Manageable):
    def __init__(self, host: str, port: int, manager: Manager):
        super().__init__(manager)
        self.host = host
        self.port = port

    async def ping(self, _availability_hint: bool | None = None):
        async def _connect(connect_timeout: float):
            logger.debug(" Connecting to %s on port %d (timeout is %ds)", self.host, self.port, connect_timeout)
            async with asyncio.timeout(connect_timeout):
                return await asyncio.open_connection(self.host, self.port)
        logger.debug("Pinging %s (%s:%d)", LazyStr(self.get_class_name), self.host, self.port)
        try:
            _reader, writer = await _connect(2)
            writer.close()
            await writer.wait_closed()
            return True
        except (TimeoutError, socket.gaierror):
            return False
        except Exception as e:
            logger.debug("  Unexpected ping exception: %s", e.__str__())
            raise

class Device(Manageable):
    def __init__(self, host: str, manager: Manager):
        super().__init__(manager)
        self.host = host

    async def ping(self, availability_hint: bool | None = None):
        logger.debug("Pinging %s (%s)", LazyStr(self.get_class_name), self.host)
        return await async_ping(self.host, timeout=2)

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

class State:
    WIFI = 'wifi'
    PFTPD = 'pftpd'
    NAMES = { WIFI: "Wi-Fi", PFTPD: "pFTPd"}

    @abstractmethod
    async def get(self, repeat: float, timeout: float) -> dict:
        pass

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

class AutomatepFTPd(Manager):
    def __init__(self, automate: Automate):
        self.automate = automate

    async def start(self):
        await self.automate.send_message('start-pftpd')

    async def stop(self):
        await self.automate.send_message('stop-pftpd')

class AutomateTailscale(Manager):
    def __init__(self, automate: Automate):
        self.automate = automate

    async def start(self):
        await self.automate.send_message('start-tailscale')

    async def stop(self):
        await self.automate.send_message('stop-tailscale')

class AutomateState(State):
    VARIABLE_STATE = 'state'

    def __init__(self, session: aiohttp.ClientSession, webhooks: Webhooks, automate: Automate, external_url: str):
        self.session = session
        self.webhooks = webhooks
        self.automate = automate
        self.external_url = external_url

    async def get(self, repeat: float, timeout: float):
        logger.info("Getting state...")
        # first test funnel + webhooks availability, to not wait for a reply if local tailscale or funnel is down
        try:
            async with self.session.get(f'{self.external_url}{Webhooks.get_ping_path()}') as response:
                if await response.text() != 'pong':
                    raise Exception()
        except:
            raise RuntimeError(f"Local Tailscale is down or local Funnel is not configured properly for {self.external_url}")
        # get state
        self.webhooks.subscribe_variable(AutomateState.VARIABLE_STATE)
        try:
            async with asyncio.timeout(timeout):
                while True:
                    try:
                        await self.automate.send_message(f'get-state;{self.external_url}{Webhooks.get_variable_path(AutomateState.VARIABLE_STATE)}')
                        state = await self.webhooks.get_variable(AutomateState.VARIABLE_STATE, min(repeat, timeout))
                        break
                    except TimeoutError:
                        pass
        except TimeoutError as e:
            e.add_note(f"Can't get value of {AutomateState.VARIABLE_STATE} for {timeout} seconds")
            raise
        finally:
            self.webhooks.unsubscribe_variable(AutomateState.VARIABLE_STATE)
        logger.info("  state is %s", state)
        return StateSerializer.loads(state)

########

class Cache:
    PRIM_SYNC_APP_NAME = 'prim-sync'

    def __init__(self):
        self.cache_path = Path(user_cache_dir(Cache.PRIM_SYNC_APP_NAME, False))

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

class ZeroconfService(Manageable):
    def __init__(self, service_name: str, service_cache: ServiceCache, service_resolver: ServiceResolver, manager: Manager):
        super().__init__(manager)
        self.service_name = service_name
        self.host = None
        self.port = None
        self.service_cache = service_cache
        self.service_resolver = service_resolver

    async def ping(self, availability_hint: bool | None = None):
        async def _connect(connect_timeout: float, resolve_timeout: float):
            async def asyncio_open_connection(host: str, port: int, timeout: float):
                logger.debug(" Connecting to %s on port %d (timeout is %ds)", host, port, timeout)
                async with asyncio.timeout(timeout):
                    return await asyncio.open_connection(host, port)
            async def service_resolver_get(service_name: str, timeout: float):
                logger.debug(" Resolving %s (timeout is %ds)", service_name, timeout)
                return await self.service_resolver.get(service_name, timeout)
            if self.host and self.port:
                return await asyncio_open_connection(self.host, self.port, connect_timeout)
            host, port = self.service_cache.get(self.service_name)
            if host and port:
                try:
                    reader_writer = await asyncio_open_connection(host, port, connect_timeout)
                    self.host = host
                    self.port = port
                    return reader_writer
                except (TimeoutError, socket.gaierror):
                    if availability_hint is None or availability_hint:
                        pass
                    else:
                        raise
            host, port = await service_resolver_get(self.service_name, resolve_timeout)
            reader_writer = await asyncio_open_connection(host, port, connect_timeout)
            self.service_cache.set(self.service_name, host, port)
            self.host = host
            self.port = port
            return reader_writer
        logger.debug("Pinging %s (%s - %s:%s)", LazyStr(self.get_class_name), self.service_name, str(self.host), str(self.port))
        try:
            _reader, writer = await _connect(2, 6)
            writer.close()
            await writer.wait_closed()
            return True
        except (TimeoutError, socket.gaierror):
            return False
        except Exception as e:
            logger.debug("  Unexpected ping exception: %s", e.__str__())
            raise

########

class Phone:
    def __init__(self, local_sftp: ZeroconfService, vpn: Device | None, remote_sftp: Service | None, state: State | None):
        self.local_sftp = local_sftp
        self.vpn = vpn
        self.remote_sftp = remote_sftp
        self.state = state

class pFTPdServiceListener(ServiceListener):
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

class pFTPd(Service):
    pass

class pFTPdZeroconf(ZeroconfService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__qualname__ = pFTPd.__qualname__

class Tailscale(Device):
    def __init__(self, tailnet: str, machine_name: str, manager: Manager):
        super().__init__(f'{machine_name}.{tailnet}', manager)
        self.tailnet = tailnet

class Funnel:
    LOCAL_HOST = '127.0.0.1'

    def __init__(self, tailscale: Tailscale, machine_name: str, local_port: int, local_path: str, external_port: int):
        self.local_port = local_port
        self.external_url = f'https://{machine_name}.{tailscale.tailnet}:{external_port}{local_path}'

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
    WIFI = 'wifi'
    VPN = 'vpn'
    SFTP = 'sftp'
    ADDRESS = 'address'

    @staticmethod
    def setup_parser_arguments(parser):
        parser.add_argument('server_name', metavar='server-name', help="the Servername configuration option from Primitive FTPd app")
        parser.add_argument('-i', '--intent', choices=["test", "start", "stop"], help="what to do with the apps, default: test", default="test")

    @staticmethod
    def setup_parser_options(parser):
        pass

    @staticmethod
    def setup_parser_groups(parser):
        logging_group = parser.add_argument_group('logging')
        logging_group.add_argument('-t', '--timestamp', help="prefix each message with an UTC timestamp", default=False, action='store_true')
        logging_group.add_argument('-s', '--silent', help="only errors printed", default=False, action='store_true')
        logging_group.add_argument('--debug', help="use debug level logging and add stack trace for exceptions, overrides the --silent option", default=False, action='store_true')

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
        logger.prepare(args.timestamp, args.silent)

        if args.accept_cellular and args.intent != 'start':
            raise ValueError("The --accept-cellular options can be enabled only for the start intent")
        if args.backup_state and args.intent != 'start':
            raise ValueError("The --backup-state option can be enabled only for the start intent")
        if args.restore_state and args.intent != 'stop':
            raise ValueError("The --restore-state option can be enabled only for the stop intent")

    async def execute(self, args, phone: Phone):
        async def _stop(restore_state: dict | None):
            if phone.vpn and phone.remote_sftp and await phone.vpn.test():
                if (restore_state is None or not restore_state.get(Control.SFTP, False)) and await phone.remote_sftp.test():
                    await phone.remote_sftp.stop(10, 30)
                if restore_state is None or not restore_state.get(Control.VPN, False):
                    await phone.vpn.stop(10, 60)
            else:
                if (restore_state is None or not restore_state.get(Control.SFTP, False)):
                    await phone.local_sftp.stop(10, 30)
        match args.intent:
            case 'test':
                if phone.vpn and phone.remote_sftp and phone.state:
                    phone_state, _vpn_state = await gather_with_taskgroup(phone.state.get(10, 30), phone.vpn.test())
                    for k, v in phone_state.items():
                        logger.info("%s is %s", LazyStr(lambda: State.NAMES[k]), LazyStr(StateSerializer.dump_value, v))
                elif phone.vpn and phone.remote_sftp and await phone.vpn.test():
                    await phone.remote_sftp.test()
                else:
                    await phone.local_sftp.test()
            case 'start':
                if phone.vpn and phone.remote_sftp and phone.state:
                    phone_state, vpn_state = await gather_with_taskgroup(phone.state.get(10, 30), phone.vpn.test())
                    state = dict()
                    state[Control.WIFI] = phone_state[State.WIFI]
                    state[Control.VPN] = vpn_state
                    state[Control.SFTP] = phone_state[State.PFTPD]
                    if not state[Control.WIFI] and not args.accept_cellular:
                        raise RuntimeError(f"Phone is not on Wi-Fi network")
                    # make sftp accessible
                    try:
                        local_accessible = False
                        remote_accessible = False
                        if not state[Control.SFTP]:
                            if not state[Control.VPN]:
                                if state[Control.WIFI]:
                                    try:
                                        await phone.local_sftp.start(10, 30)
                                        local_accessible = True
                                    except TimeoutError:
                                        await phone.vpn.start(10, 60)
                                        remote_accessible = await phone.remote_sftp.test()
                                else:
                                    await phone.vpn.start(10, 60)
                                    await phone.remote_sftp.start(10, 30)
                                    remote_accessible = True
                            else:
                                # Note: even we test the remote accessibility during start, this doesn't disclose the possibility, that sftp will be accessible locally
                                #       but sure it is an error, if it doesn't accessible even remotely
                                await phone.remote_sftp.start(10, 30)
                                remote_accessible = True
                                if state[Control.WIFI]:
                                    local_accessible = await phone.local_sftp.test()
                        else:
                            if not state[Control.VPN]:
                                if not state[Control.WIFI] or not (local_accessible := await phone.local_sftp.test()):
                                    await phone.vpn.start(10, 60)
                                    remote_accessible = await phone.remote_sftp.test()
                            else:
                                local_accessible, remote_accessible = await gather_with_taskgroup(phone.local_sftp.test(), phone.remote_sftp.test())
                        if not local_accessible and not remote_accessible:
                            raise RuntimeError(f"Even when {phone.vpn.get_class_name()} and {phone.remote_sftp.get_class_name()} is started, {phone.remote_sftp.get_class_name()} is still not accessible")
                    except:
                        # restore state
                        await _stop(state)
                        raise
                    # backup state
                    if args.backup_state:
                        if not local_accessible:
                            state[Control.ADDRESS] = '|'.join([phone.remote_sftp.host, str(phone.remote_sftp.port)])
                        print(StateSerializer.dumps(state))
                elif phone.vpn and phone.remote_sftp:
                    if not await phone.vpn.test():
                        # Note: in this case (without state) it is possible that the phone is on another Wi-Fi (or cellular) and local_sftp's test() and start() will be false negative
                        #       but it worth a try, and when it fails, we can still try to start the vpn up
                        if not await phone.local_sftp.test():
                            try:
                                await phone.local_sftp.start(10, 30)
                            except TimeoutError:
                                await phone.vpn.start(10, 60)
                                if not await phone.remote_sftp.test():
                                    raise RuntimeError(f"Even when {phone.vpn.get_class_name()} and {phone.remote_sftp.get_class_name()} is started, {phone.remote_sftp.get_class_name()} is still not accessible")
                    else:
                        # Note: even we test the remote accessibility during start, this doesn't disclose the possibility, that sftp will be accessible locally
                        #       but sure it is an error, if it doesn't accessible even remotely
                        if not any(await gather_with_taskgroup(phone.local_sftp.test(), phone.remote_sftp.test())):
                            await phone.remote_sftp.start(10, 30)
                else:
                    # Note: in this case (without state and vpn) it is possible that the phone is on another Wi-Fi (or cellular) and local_sftp's test() and start() will be false negative
                    #       but we have no more options, this is a best effort
                    if not await phone.local_sftp.test():
                        await phone.local_sftp.start(10, 30)
            case 'stop':
                await _stop(StateSerializer.loads(args.restore_state) if args.restore_state else None)

class AutomateControl(Control):
    @staticmethod
    def setup_subparser(subparsers):
        parser = subparsers.add_parser('Automate', aliases=['a'],
            description="Remote management of your phone's Primitive FTPd and optionally Tailscale app statuses via the Automate app\n\n"
                "Note: you must install Automate app on your phone, download prim-ctrl flow into it, and configure your Google account in the flow to receive messages (see the project's GitHub page for more details)\n"
                "Note: optionally if your phone is not accessible on local network but your laptop is part of the Tailscale VPN then Tailscale VPN can be started on the phone\n"
                "Note: optionally if your laptop is accessible through Tailscale funnel then app statuses on the phone can be backed up and restored",
            formatter_class=WideHelpFormatter)

        parser.add_argument('automate_account', metavar='automate-account', help="your Google account email you set up in the Automate flow's first Set variable block's Value field")
        parser.add_argument('automate_device', metavar='automate-device', help="the device name you can see at the Automate flow's Cloud receive block's This device field")
        parser.add_argument('automate_tokenfile', metavar='automate-tokenfile', help="filename containing Automates's Secret that located under your .secrets folder\n"
                            "(generated on https://llamalab.com/automate/cloud, use the same Google account you set up on the Cloud receive block)")

        Control.setup_parser_arguments(parser)

        Control.setup_parser_options(parser)

        Control.setup_parser_groups(parser)

        vpn_group = parser.add_argument_group('VPN',
            description="To use --tailscale option you must install Tailscale and configure Tailscale VPN on your phone and your laptop\n"
                "To use --funnel option you must configure Tailscale funnel on your laptop for prim-ctrl's local webhook to accept responses from the Automate app\n"
                "(eg.: tailscale funnel --bg --https=8443 --set-path=/prim-ctrl \"http://127.0.0.1:12345\")\n"
                "Note: --funnel and --restore-state options can be used only when --tailscale is used\n"
                "Note: --accept-cellular and --backup-state options can be used only when --funnel is used")
        vpn_group.add_argument('--tailscale', nargs=3, metavar=('tailnet', 'remote-machine-name', 'sftp-port'), help=
                            "tailnet:             your Tailscale tailnet name (eg. tailxxxx.ts.net)\n"
                            "remote-machine-name: your phone's name within your tailnet (just the name, without the tailnet)\n"
                            "sftp-port:           Primitive FTPd's sftp port")
        vpn_group.add_argument('--funnel', nargs=4, metavar=('local-machine-name', 'local-port', 'local-path', 'external-port'), help=
                            "local-machine-name:  your laptop's name within your tailnet (just the name, without the tailnet)\n"
                            "local-port:          12345 - if you used the example tailscale funnel command above (the local webhook will be started on this port)\n"
                            "local-path:          /prim-ctrl - if you used the example tailscale funnel command above\n"
                            "external-port:       8443 - if you used the example tailscale funnel command above")
        Control.setup_parser_vpngroup(vpn_group)

        parser.set_defaults(ctor=AutomateControl)

    def prepare(self, args):
        super().prepare(args)
        if args.funnel and not args.tailscale:
            raise ValueError("--funnel option can be used only when --tailscale is used")
        if args.restore_state and not args.tailscale:
            raise ValueError("--restore-state option can be used only when --tailscale is used")
        if args.accept_cellular and not args.funnel:
            raise ValueError("--accept-cellular option can be used only when --funnel is used")
        if args.backup_state and not args.funnel:
            raise ValueError("--backup-state option can be used only when --funnel is used")

    async def run(self, args):
        self.prepare(args)

        async with aiohttp.ClientSession(
                # Automate messaging server prefers closing connections
                connector=aiohttp.TCPConnector(force_close=True)) as session:
            async with AsyncZeroconf() as zeroconf:
                service_cache = ServiceCache(Cache())
                service_resolver = SftpServiceResolver(zeroconf)
                service_listener = pFTPdServiceListener(args.server_name, service_cache)
                service_browser = SftpServiceBrowser(zeroconf)
                await service_browser.add_service_listener(service_listener)

                automate = Automate(Secrets(), session, args.automate_account, args.automate_device, args.automate_tokenfile)
                local_pftpd = pFTPdZeroconf(args.server_name, service_cache, service_resolver, AutomatepFTPd(automate))
                tailscale = Tailscale(args.tailscale[0], args.tailscale[1], AutomateTailscale(automate)) if args.tailscale else None
                remote_pftpd = pFTPd(tailscale.host, int(args.tailscale[2]), local_pftpd.manager) if tailscale else None
                funnel = Funnel(tailscale, args.funnel[0], int(args.funnel[1]), args.funnel[2], int(args.funnel[3])) if tailscale and args.funnel else None

                async with Webhooks(Funnel.LOCAL_HOST, funnel.local_port) if funnel else nullcontext() as webhooks:
                    state = AutomateState(session, webhooks, automate, funnel.external_url) if funnel and webhooks else None
                    phone = Phone(local_pftpd, tailscale, remote_pftpd, state)
                    await self.execute(args, phone)

async def main():
    args = None
    try:
        parser = argparse.ArgumentParser(
            description="Remote management of your phone's Primitive FTPd and Tailscale app statuses via the Automate app",
            formatter_class=WideHelpFormatter)
        subparsers = parser.add_subparsers(required=True,
            title="Phone app to use for control")

        AutomateControl.setup_subparser(subparsers)

        args = parser.parse_args()
        await args.ctor().run(args)

    except Exception as e:
        if not args or args.debug:
            logger.exception(e)
        else:
            logger.error(repr(e))

if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
    exit(logger.exitcode)
