
import argparse
import asyncio
import logging
import os
import re
import sys
import time
from abc import abstractmethod
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Tuple

import aiohttp
import ntplib
from aiohttp import web, ClientConnectorError
from attr import dataclass
from hass_client import HomeAssistantClient as HomeAssistantWebsocketClient
from hass_client.models import Event
from ntplib import NTPException
from tailscale import Device
from tailscale import Tailscale as TailscaleApi

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

logger = Logger(Path(sys.argv[0]).name)

########

def get_secret(tokenfile:str):
    with open(str(Path.home() / ".secrets" / tokenfile), 'rt') as file:
        return file.readline().rstrip()

def set_secret(tokenfile:str, token: str):
    with open(str(Path.home() / ".secrets" / tokenfile), 'wt') as file:
        file.write(token)

def get_secret_age(tokenfile:str):
    return (datetime.now(timezone.utc) - datetime.fromtimestamp(os.stat(str(Path.home() / ".secrets" / tokenfile)).st_mtime, timezone.utc)).total_seconds()

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
            return await asyncio.wait_for(queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get value of {variable} for {timeout} seconds")

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
    def __init__(self, session: aiohttp.ClientSession, account: str, device: str, tokenfile: str):
        self.session = session
        self.account = account
        self.device = device
        self.secret = get_secret(tokenfile)
        self.headers = {
            "content-type": "application/json",
        }
    async def send_message(self, message: str, high_priority: bool = False):
        data = {
            "secret": self.secret,
            "to": self.account,
            "device": self.device,
            "priority": "high" if high_priority else "normal",
            "payload": f"prim-ctrl;{time.time()};" + message
        }
        async with self.session.post(f'https://llamalab.com/automate/cloud/message', json=data) as response:
            await response.text()

class HomeAssistantWebsocket(HomeAssistantWebsocketClient):
    COMMAND_UPDATE_SENSORS_NOTIFICATION_RECEIVED = 'command_update_sensors_notification_received'

    def __init__(self, session: aiohttp.ClientSession, host: str, tokenfile: str):
        super().__init__(f'wss://{host}/api/websocket', get_secret(tokenfile), session)
        self.event_subscriptions = dict[str, Tuple[Callable, asyncio.Queue[Event]]]()

    async def subscribe_event(self, subscription: str, event_type: str, filter: Callable[[Event], bool]):
        def _event_handler(event: Event):
            subscription_data = self.event_subscriptions.get(subscription)
            if subscription_data:
                _unsubscribe, queue = subscription_data
                if filter(event):
                    with suppress(asyncio.QueueFull):
                        queue.put_nowait(event)
        if subscription not in self.event_subscriptions:
            unsubscribe = await self.subscribe_events(_event_handler, event_type)
            self.event_subscriptions[subscription] = (unsubscribe, asyncio.Queue[Event](maxsize=16))

    def unsubscribe_event(self, subscription: str):
        subscription_data = self.event_subscriptions.pop(subscription, None)
        if subscription_data:
            unsubscribe, _queue = subscription_data
            unsubscribe()
    
    async def subscribe_command_update_sensors_notification_received_event(self):
        def _filter_command_update_sensors_notification_received(event: Event) -> bool:
            if data := event.get('data'):
                if message := data.get('message'):
                    if message == 'command_update_sensors':
                        return True
            return False
        await self.subscribe_event(HomeAssistantWebsocket.COMMAND_UPDATE_SENSORS_NOTIFICATION_RECEIVED, 'mobile_app_notification_received', _filter_command_update_sensors_notification_received)

    def unsubscribe_command_update_sensors_notification_received_event(self):
        self.unsubscribe_event(HomeAssistantWebsocket.COMMAND_UPDATE_SENSORS_NOTIFICATION_RECEIVED)

    async def get_event(self, subscription: str, timeout: float):
        subscription_data = self.event_subscriptions.get(subscription)
        if not subscription_data:
            raise ValueError(f"The {subscription} is unknown")
        _unsubscribe, queue = subscription_data
        try:
            return await asyncio.wait_for(queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get event for {subscription} for {timeout} seconds")

    async def get_command_update_sensors_notification_received_event(self, timeout: float):
        await self.get_event(HomeAssistantWebsocket.COMMAND_UPDATE_SENSORS_NOTIFICATION_RECEIVED, timeout)

    def __enter__(self):
        raise TypeError("Use async with instead")
    def __exit__(self, exc_type, exc_value, exc_tb):
        pass
    async def __aenter__(self):
        await super().__aenter__()
        return self
    async def __aexit__(self, exc_type, exc_value, exc_tb):
        return await super().__aexit__(exc_type, exc_value, exc_tb)

class HomeAssistant():
    def __init__(self, session: aiohttp.ClientSession, host: str, phone: str, tokenfile: str):
        self.session = session
        self.host = host
        self.phone = phone
        self.headers = {
            "Authorization": "Bearer " + get_secret(tokenfile),
            "content-type": "application/json",
        }

    async def _get_api(self, path: str):
        async with self.session.get(f'https://{self.host}{path}', headers=self.headers) as response:
            return await response.json()

    async def _post_api(self, path: str, data):
        async with self.session.post(f'https://{self.host}{path}', headers=self.headers, json=data) as response:
            return await response.json()

    async def get_state(self, entity_id: str):
        return await self._get_api(f'/api/states/{entity_id}')

    async def _call_service(self, domain: str, service: str, service_data):
        return await self._post_api(f'/api/services/{domain}/{service}', service_data)

    async def _notify(self, message: str, message_data):
        service_data = {
            "message": message,
            "data": message_data}
        return await self._call_service('notify', f'mobile_app_{self.phone}', service_data)

    async def update_sensors(self):
        message_data = {
            "priority": "high",
            "ttl": 0,
            "confirmation": True}
        return await self._notify("command_update_sensors", message_data)

    async def broadcast_intent(self, package_name: str, action: str):
        message_data = {
            "intent_package_name": package_name,
            "intent_action": action}
        return await self._notify("command_broadcast_intent", message_data)

    async def start_activity(self, package_name: str, class_name: str, action: str):
        message_data = {
            "intent_package_name": package_name,
            "intent_class_name": class_name,
            "intent_action": action}
        return await self._notify("command_activity", message_data)

class Tailscale():
    TOKEN_SUFFIX = '.token'

    def __init__(self, session: aiohttp.ClientSession, tailnet: str, machine_name: str, secretfile: str):
        self.session = session
        self.tailnet = tailnet
        self.machine_name = machine_name
        self.secretfile = secretfile
        self.tailscale_client = None
        self.deviceid = None

    async def _start(self):
        # create new access_token from client_secret if previous access_token is expired or nonexistent
        tokenfile = self.secretfile + Tailscale.TOKEN_SUFFIX
        token = None
        try:
            if 3300 > get_secret_age(tokenfile):
                token = get_secret(tokenfile)
        except FileNotFoundError:
            pass
        if token is None:
            secret = get_secret(self.secretfile)
            client_id = secret.split('-')[2]
            data = {
                "client_id": client_id,
                "client_secret": secret,
                "grant_type": "client_credentials",
                "scope" : "devices:read"
            }
            async with self.session.post('https://api.tailscale.com/api/v2/oauth/token', data=data) as response:
                json_response = await response.json()
            expires_in = json_response.get('expires_in')
            token = json_response.get('access_token')
            assert expires_in is not None and token is not None
            if expires_in < 3600:
                raise RuntimeError(f'Tailscale access token received shorter that 1 hour, {expires_in} seconds expiration')
            set_secret(tokenfile, token)
        self.tailscale_client = TailscaleApi(tailnet=self.tailnet, api_key=token, session=self.session)

    async def device(self) -> Device:
        assert self.tailscale_client is not None
        if not self.deviceid:
            devices = await self.tailscale_client.devices()
            devicename = f'{self.machine_name}.{self.tailnet}'
            for device in devices.values():
                if device.name == devicename:
                    self.deviceid = device.device_id
                    break
            if not self.deviceid:
                raise RuntimeError(f"Device {self.machine_name} in {self.tailnet} is unknown by Tailscale")
        data = await self.tailscale_client._request(f"device/{self.deviceid}?fields=all")
        return Device.from_json(data)

    ntp_is_accessed = False
    ntp_offset: timedelta
    ping_limit: int

    async def ping_device(self):
        last_seen = (await self.device()).last_seen
        if last_seen is None:
            logger.debug("Tailscale.ping_device() last_seen=None")
            return False
        else:
            now = datetime.now(timezone.utc)
            if not self.ntp_is_accessed:
                try:
                    ntpclient = ntplib.NTPClient()
                    ntpstats = ntpclient.request('pool.ntp.org', version=3)
                    self.ntp_offset = timedelta(seconds=ntpstats.offset)
                    self.ping_limit = 3
                except NTPException:
                    logger.warning("NTP is unavailable, Tailscale device availability testing is slower and inaccurate")
                    self.ntp_offset = timedelta(0)
                    self.ping_limit = 6
                finally:
                    self.ntp_is_accessed = True
            difference = (now + self.ntp_offset - last_seen).total_seconds()
            logger.debug("Tailscale.ping_device() last_seen=%s now=%s offset=%s difference=%s", last_seen, now, self.ntp_offset, difference)
            return self.ping_limit > difference
    
    async def wait_for_device(self, available: bool, timeout: float):
        async def _while():
            while await self.ping_device() != available:
                await asyncio.sleep(2)
        await asyncio.wait_for(_while(), timeout)
        if available:
            # TS refreshes the peer state quite fast, we have to wait a little for the tun0 interface to be ready
            await asyncio.sleep(2)

    def __enter__(self):
        raise TypeError("Use async with instead")
    def __exit__(self, exc_type, exc_value, exc_tb):
        pass
    async def __aenter__(self):
        await self._start()
        return self
    async def __aexit__(self, exc_type, exc_value, exc_tb):
        pass

@dataclass
class Funnel:
    LOCAL_HOST = '127.0.0.1'

    local_port: int
    local_path: str
    machine_name: str
    external_port: int

    def get_url(self, tailnet: str):
        return f'https://{self.machine_name}.{tailnet}:{self.external_port}{self.local_path}'

########

class Phone:
    def __init__(self, tailscale: Tailscale, sftp_port: int, ssh_port: int):
        self.tailscale = tailscale
        self.sftp_port = sftp_port
        self.ssh_port = ssh_port

    @abstractmethod
    async def get_network_type(self, timeout: float) -> str:
        pass

    @abstractmethod
    async def start_tailscale(self):
        pass

    @abstractmethod
    async def stop_tailscale(self):
        pass

    @abstractmethod
    async def start_pftpd(self):
        pass

    @abstractmethod
    async def stop_pftpd(self):
        pass

    @abstractmethod
    async def start_termux_sshd(self):
        pass

    @abstractmethod
    async def stop_termux_sshd(self):
        pass

    @staticmethod
    def _get_service_state(available: bool):
        return 'up' if available else 'down'

    async def test_tailscale(self):
        available = await self.tailscale.ping_device()
        logger.info("Tailscale is %s", Phone._get_service_state(available))
        return available

    async def wait_for_tailscale(self, available: bool, timeout: float):
        try:
            await self.tailscale.wait_for_device(available, timeout)
            logger.info("Tailscale is %s", Phone._get_service_state(available))
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get Tailscale {Phone._get_service_state(available)} for {timeout} seconds")

    async def _connect_remote_port(self, port: int):
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(self.tailscale.machine_name + '.' + self.tailscale.tailnet, port), timeout=2)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            pass
        return False

    async def _wait_for_remote_port(self, port: int, available: bool, timeout: float):
        async def _while():
            while await self._connect_remote_port(port) != available:
                await asyncio.sleep(1)
        await asyncio.wait_for(_while(), timeout)

    async def test_pftpd(self):
        available = await self._connect_remote_port(self.sftp_port)
        logger.info("pFTPd is %s", Phone._get_service_state(available))
        return available

    async def wait_for_pftpd(self, available: bool, timeout: float):
        try:
            await self._wait_for_remote_port(self.sftp_port, available, timeout)
            logger.info("pFTPd is %s", Phone._get_service_state(available))
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get pFTPd {Phone._get_service_state(available)} for {timeout} seconds")

    async def test_termux_sshd(self):
        available = await self._connect_remote_port(self.ssh_port)
        logger.info("Termux's sshd is %s", Phone._get_service_state(available))
        return available

    async def wait_for_termux_sshd(self, available: bool, timeout: float):
        try:
            await self._wait_for_remote_port(self.ssh_port, available, timeout)
            logger.info("Termux's sshd is %s", Phone._get_service_state(available))
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get Termux's sshd {Phone._get_service_state(available)} for {timeout} seconds")

class AutomatePhone(Phone):
    VARIABLE_NETWORK_INTERFACE = 'network_interface'

    NETWORK_TYPE_BY_INTERFACE_NAME = {
        "rmnet": "cellular",
        "wlan": "wifi",
        "tun": "vpn",
        # "p2p": "wifi_aware",
        # "rndis": "usb",
        # "eth": "ethernet",
    }

    def __init__(self, session: aiohttp.ClientSession, webhooks: Webhooks, automate: Automate, funnel: Funnel, tailscale: Tailscale,
            sftp_port: int, ssh_port: int):
        super().__init__(tailscale, sftp_port, ssh_port)
        self.session = session
        self.webhooks = webhooks
        self.automate = automate
        self.funnel = funnel

    async def get_network_type(self, timeout: float):
        logger.info("Getting network type")
        funnel_url = self.funnel.get_url(self.tailscale.tailnet)
        # first test funnel + webhooks availability, to not wait for a reply if local tailscale or funnel is down
        try:
            async with self.session.get(f'{funnel_url}{Webhooks.get_ping_path()}') as response:
                if await response.text() != 'pong':
                    raise Exception()
        except:
            raise RuntimeError(f"Local Tailscale is down or local Funnel is not configured properly for {funnel_url}")
        # get network interface
        self.webhooks.subscribe_variable(AutomatePhone.VARIABLE_NETWORK_INTERFACE)
        async def _get_network_type():
            await self.automate.send_message(
                f'get-network-interface;{funnel_url}{Webhooks.get_variable_path(AutomatePhone.VARIABLE_NETWORK_INTERFACE)}',
                True)
            return await self.webhooks.get_variable(AutomatePhone.VARIABLE_NETWORK_INTERFACE, min(5, timeout))
        async def _get_network_type_repeatedly():
            while True:
                try:
                    return await _get_network_type()
                except TimeoutError:
                    pass
        try:
            network_interface = await asyncio.wait_for(_get_network_type_repeatedly(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Can't get value of {AutomatePhone.VARIABLE_NETWORK_INTERFACE} for {timeout} seconds")
        finally:
            self.webhooks.unsubscribe_variable(AutomatePhone.VARIABLE_NETWORK_INTERFACE)
        # get network type
        network_interface = re.findall(r'^(.*?)\d*$', network_interface)[0] # drop trailing digits
        network_type = AutomatePhone.NETWORK_TYPE_BY_INTERFACE_NAME.get(network_interface, network_interface)
        logger.info("  network type is %s", network_type)
        return network_type

    async def start_tailscale(self):
        logger.info("Starting Tailscale")
        await self.automate.send_message('start-tailscale')

    async def stop_tailscale(self):
        logger.info("Stopping Tailscale")
        await self.automate.send_message('stop-tailscale')

    async def start_pftpd(self):
        logger.info("Starting pFTPd")
        await self.automate.send_message('start-pftpd')

    async def stop_pftpd(self):
        logger.info("Stoping pFTPd")
        await self.automate.send_message('stop-pftpd')

    async def start_termux_sshd(self):
        logger.info("Starting Termux sshd")
        await self.automate.send_message('start-termux-sshd')

    async def stop_termux_sshd(self):
        logger.info("Stoping Termux sshd")
        await self.automate.send_message('stop-termux-sshd')

class HomeAssistantPhone(Phone):
    def __init__(self, homeassistant_websocket: HomeAssistantWebsocket, homeassistant: HomeAssistant, tailscale: Tailscale,
            sftp_port: int, ssh_port: int):
        super().__init__(tailscale, sftp_port, ssh_port)
        self.homeassistant_websocket = homeassistant_websocket
        self.homeassistant = homeassistant
        self.tailscale = tailscale
        self.sftp_port = sftp_port

    async def get_network_type(self, timeout: float):
        logger.info("Getting network type")
        await self.homeassistant_websocket.subscribe_command_update_sensors_notification_received_event()
        await self.homeassistant.update_sensors()
        await self.homeassistant_websocket.get_command_update_sensors_notification_received_event(timeout)
        # wait a little, until HA refreshes the state
        await asyncio.sleep(1)
        network_type = (await self.homeassistant.get_state(f'sensor.{self.homeassistant.phone}_network_type'))['state']
        self.homeassistant_websocket.unsubscribe_command_update_sensors_notification_received_event()
        logger.info("  network type is %s", network_type)
        return network_type
    
    async def _tailscale(self, run: bool):
        return await self.homeassistant.broadcast_intent(
            "com.tailscale.ipn",
            "com.tailscale.ipn." + ("CONNECT_VPN" if run else "DISCONNECT_VPN"))

    async def start_tailscale(self):
        logger.info("Starting Tailscale")
        result = await self._tailscale(True)
        await self.homeassistant.update_sensors()
        return result

    async def stop_tailscale(self):
        logger.info("Stopping Tailscale")
        result = await self._tailscale(False)
        await self.homeassistant.update_sensors()
        return result

    async def _pftpd(self, run: bool):
        return await self.homeassistant.start_activity(
            "org.primftpd.lmagyar",
            "org.primftpd.ui." + ("StartServerAndExitActivity" if run else "StopServerAndExitActivity"),
            "android.intent.action.MAIN")

    async def start_pftpd(self):
        logger.info("Starting pFTPd")
        return await self._pftpd(True)

    async def stop_pftpd(self):
        logger.info("Stoping pFTPd")
        return await self._pftpd(False)
    
    async def start_termux_sshd(self):
        raise NotImplementedError("Sending RUN_COMMAND is not supported by HomeAssistant, and will never be supported, see: https://github.com/home-assistant/android/issues/4080")

    async def stop_termux_sshd(self):
        raise NotImplementedError("Sending RUN_COMMAND is not supported by HomeAssistant, and will never be supported, see: https://github.com/home-assistant/android/issues/4080")

########

class WideHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 35, width: int | None = None) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)

class StateSerializer:
    BOOL = {False : 'down', True: 'up'}
    INV_BOOL = {v: k for k, v in BOOL.items()}

    @staticmethod
    def dumps(d: dict):
        return ','.join(f"{k}={v if not isinstance(v, bool) else StateSerializer.BOOL[v]}" for k, v in d.items())

    @staticmethod
    def loads(s: str):
        try:
            return dict({k:v if v not in StateSerializer.INV_BOOL else StateSerializer.INV_BOOL[v] for k, v in [s.split('=') for s in s.split(',')]})
        except ValueError as e:
            e.add_note("Missing '=' in state")
            raise

class Control:
    NETWORK_TYPE = 'network'
    TAILSCALE = 'tailscale'
    PFTPD = 'sftp'
    TERMUX_SSHD = 'ssh'

    @staticmethod
    def setup_parser(parser):
        parser.add_argument('tailscale_tailnet', metavar='tailscale-tailnet', help="your Tailscale tailnet name (eg. tailxxxx.ts.net)")
        parser.add_argument('tailscale_remote_machine_name', metavar='tailscale-remote-machine-name', help="your phone's name within your tailnet (just the name, without the tailnet)")
        parser.add_argument('tailscale_secretfile', metavar='tailscale-secretfile', help="filename containing Tailscale's Client secret (not API access token, not Auth key) that located under your .secrets folder (generated on https://login.tailscale.com/admin/settings/oauth, with 'devices:read' scope, save only the Client secret in the file, the Client ID is part of it)")

        parser.add_argument('sftp_port', metavar='sftp-port', help="Primitive FTPd's sftp port, for availability test")
        parser.add_argument('ssh_port', nargs='?', metavar='ssh-port', help="Termux's ssh port, for availability test, optional")

        parser.add_argument('-s', '--silent', help="only errors printed", default=False, action='store_true')
        parser.add_argument('-t', '--timestamp', help="prefix each message with an UTC timestamp", default=False, action='store_true')

        parser.add_argument('-i', '--intent', choices=["test", "start", "stop"], help="what to do with the apps, default: test", default="test")
        parser.add_argument('-f', '--force-test', help="in case of start, if Tailscale is already up, don't return error, but stop everything to test underlying network type (wifi or cellular) then start everything up again", default=False, action='store_true')
        parser.add_argument('-av', '--accept-vpn', help="in case of start, if Tailscale is already up, don't return error, accept it, though ensure everything is started", default=False, action='store_true')
        parser.add_argument('-ac', '--accept-cellular', help="in case of start, if the network type is cellular, don't return error, but start everything up", default=False, action='store_true')
        parser.add_argument('-b', '--backup-state', help="in case of start, backup current state to stdout as single string (in case of an error, it will even try to restore the original state)", default=False, action='store_true')
        parser.add_argument('-r', '--restore-state', metavar="STATE", help="in case of stop, restore previous state from STATE (use -b to get a valid STATE string)", action='store')

    @abstractmethod
    async def run(self, args):
        pass

    def prepare(self, args):
        if args.force_test and args.accept_vpn:
            raise ValueError("Can't be both --force-test and --accept-vpn enabled")
        if args.intent != 'start' and (args.force_test or args.accept_vpn or args.accept_cellular):
            raise ValueError("Any of the --force-test, --accept-vpn or --accept-cellular options can be enabled only for the start intent")
        if args.intent != 'start' and args.backup_state:
            raise ValueError("The --backup-state option can be enabled only for the start intent")
        if args.intent != 'stop' and args.restore_state:
            raise ValueError("The --restore-state option can be enabled only for the stop intent")

        logger.prepare(args.timestamp, args.silent)

    async def execute(self, args, phone: Phone):
        async def _backup_state(state: dict, network_type: str):
            state[Control.NETWORK_TYPE] = network_type
            # if network_type is not vpn, tailscale can't be running, this is to protect against
            # tailscale api false-positively reporting running tailscale instance for a few seconds after manually turning it off
            tailscale = network_type == 'vpn' and await phone.test_tailscale()
            state[Control.TAILSCALE] = tailscale
            if tailscale:
                state[Control.PFTPD] = await phone.test_pftpd()
                if args.ssh_port is not None:
                    state[Control.TERMUX_SSHD] = await phone.test_termux_sshd()
        async def _start(state: dict | None):
            if state is None or not state.get(Control.TAILSCALE, False):
                await phone.start_tailscale()
                await phone.wait_for_tailscale(True, 60)
            if state is None or not state.get(Control.PFTPD, False):
                await phone.start_pftpd()
                await phone.wait_for_pftpd(True, 60)
            if args.ssh_port is not None and (state is None or not state.get(Control.TERMUX_SSHD, False)):
                await phone.start_termux_sshd()
                await phone.wait_for_termux_sshd(True, 60)
        async def _stop(state: dict | None):
            if args.ssh_port is not None and (state is None or not state.get(Control.TERMUX_SSHD, False)):
                await phone.stop_termux_sshd()
                await phone.wait_for_termux_sshd(False, 60)
            if state is None or not state.get(Control.PFTPD, False):
                await phone.stop_pftpd()
                await phone.wait_for_pftpd(False, 60)
            if state is None or not state.get(Control.TAILSCALE, False):
                await phone.stop_tailscale()
                await phone.wait_for_tailscale(False, 60)
        match args.intent:
            case 'test':
                network_type = await phone.get_network_type(60)
                # if network_type is not vpn, tailscale can't be running, this is to protect against
                # tailscale api false-positively reporting running tailscale instance for a few seconds after manually turning it off
                if network_type == 'vpn' and await phone.test_tailscale():
                    await phone.test_pftpd()
                    if args.ssh_port is not None:
                        await phone.test_termux_sshd()
            case 'start':
                state = dict()
                try:
                    network_type = await phone.get_network_type(60)
                    if network_type == 'vpn' and not args.accept_vpn:
                        if not args.force_test:
                            raise RuntimeError("Tailscale is up, can't get underlying network type", )
                        if args.backup_state:
                            await _backup_state(state, network_type)
                        await _stop(None)
                        network_type = await phone.get_network_type(30)
                    if network_type != 'vpn':
                        if network_type != 'wifi' and not args.accept_cellular:
                            raise RuntimeError(f"Phone is not on wifi network (is on {network_type})")
                    if args.backup_state and len(state) == 0:
                        await _backup_state(state, network_type)
                    await _start(state if args.backup_state else None)
                except:
                    # it's quite rudimentary, --force is not handled
                    if args.backup_state and len(state) != 0:
                        await _stop(state)
                    raise
                if args.backup_state:
                    print(StateSerializer.dumps(state))
            case 'stop':
                await _stop(StateSerializer.loads(args.restore_state) if args.restore_state else None)

class AutomateControl(Control):
    @staticmethod
    def setup_subparser(subparsers):
        parser = subparsers.add_parser('Automate', aliases=['a'],
            description="Remote management of your phone's Tailscale, Primitive FTPd and Termux's sshd app statuses via the Automate app\n\n"
                "Note: your laptop must be part of the Tailscale VPN and accessible through Tailscale funnel (eg.: tailscale funnel --bg --https=8443 --set-path=/prim-ctrl \"http://127.0.0.1:12345\")\n"
                "Note: you must install Automate on your phone, download prim-ctrl flow into it, and configure your Google account in the flow to receive mesages (see the project's GitHub page for more details)\n"
                "Note: optionally you can install Termux on your phone, and configure it to start/stop sshd on Automate's request (see the project's GitHub page for more details)",
            formatter_class=WideHelpFormatter)
        
        parser.add_argument('automate_account', metavar='automate-account', help="your Google account email you set up in the Automate flow's first Set variable block's Value field")
        parser.add_argument('automate_device', metavar='automate-device', help="the device name you can see at the Automate flow's Cloud receive block's This device field")
        parser.add_argument('automate_tokenfile', metavar='automate-tokenfile', help="filename containing Automates's Secret that located under your .secrets folder (generated on https://llamalab.com/automate/cloud, use the same Google account you set up on the Cloud receive block)")

        parser.add_argument('funnel_local_port', metavar='funnel-local-port', help="12345 - if you used the example tailscale funnel command above")
        parser.add_argument('funnel_local_path', metavar='funnel-local-path', help="/prim-ctrl - if you used the example tailscale funnel command above")
        parser.add_argument('funnel_local_machine_name', metavar='funnel-local-machine-name', help="your laptop's name within your tailnet (just the name, without the tailnet)")
        parser.add_argument('funnel_external_port', metavar='funnel-external-port', help="8443 - if you used the example tailscale funnel command above")

        Control.setup_parser(parser)

        parser.set_defaults(ctor=AutomateControl)

    async def run(self, args):
        self.prepare(args)
        async with aiohttp.ClientSession() as session:
            async with Webhooks(Funnel.LOCAL_HOST, args.funnel_local_port) as webhooks:
                async with Tailscale(session, args.tailscale_tailnet, args.tailscale_remote_machine_name, args.tailscale_secretfile) as tailscale:
                    phone = AutomatePhone(
                        session,
                        webhooks,
                        Automate(session, args.automate_account, args.automate_device, args.automate_tokenfile),
                        Funnel(args.funnel_local_port, args.funnel_local_path, args.funnel_local_machine_name, args.funnel_external_port),
                        tailscale,
                        args.sftp_port, args.ssh_port)

                    await self.execute(args, phone)

class HomeAssistantControl(Control):
    @staticmethod
    def setup_subparser(subparsers):
        parser = subparsers.add_parser('HomeAssistant', aliases=['ha'],
            description="Remote management of your phone's Tailscale, Primitive FTPd and Termux's sshd app statuses via the Home Assistant app\n\n"
                "Note: your laptop must be part of the Tailscale VPN\n"
                "Note: you must enable the Network type sensor in the Home Assistant app\n"
                "Note: optionally you can install Termux on your phone, and configure it to start/stop sshd on request (see the project's GitHub page for more details)\n"
                "      but with HomeAssistant only the availability can be tested, Home Assistant intentionally can't send intents to Termux to run commands\n"
                "      see: https://github.com/home-assistant/android/issues/4080",
            formatter_class=WideHelpFormatter)

        parser.add_argument('ha_host', metavar='ha-host', help="the Home Assistant device's hostname and optionally the port, without protocol and path (eg. my-homeassistant.duckdns.org:8123 or my-homeassistant.tailxxxx.ts.net)")
        parser.add_argument('ha_phone', metavar='ha-phone', help="device name in Home Assistant's Mobile App integration (the Entity ID behind 'device_tracker.xxx')")
        parser.add_argument('ha_tokenfile', metavar='ha-tokenfile', help="filename containing Home Assistant's Long-Lived Access Token that located under your .secrets folder")

        Control.setup_parser(parser)

        parser.set_defaults(ctor=HomeAssistantControl)

    async def run(self, args):
        self.prepare(args)
        if r'/' in args.ha_host:
            raise ValueError("Home Assistant's hostname can't contain '/' character")
        async with aiohttp.ClientSession() as session:
            async with HomeAssistantWebsocket(session, args.ha_host, args.ha_tokenfile) as homeassistant_websocket:
                async with Tailscale(session, args.tailscale_tailnet, args.tailscale_remote_machine_name, args.tailscale_secretfile) as tailscale:
                    phone = HomeAssistantPhone(
                        homeassistant_websocket,
                        HomeAssistant(session, args.ha_host, args.ha_phone, args.ha_tokenfile),
                        tailscale,
                        args.sftp_port, args.ssh_port)

                    await self.execute(args, phone)

async def main():
    try:
        parser = argparse.ArgumentParser(
            description="Remote management of your phone's Tailscale, Primitive FTPd and Termux's sshd app statuses via the Automate or Home Assistant app\n\n"
                "Note: prefer Automate, because Home Assistant's entity status of the phone's network_type can't be reliably updated,\n"
                "      and Home Assistant intentionally can't send intents to Termux to run commands",
            formatter_class=WideHelpFormatter)
        subparsers = parser.add_subparsers(required=True,
            title="Phone app to use for control")

        AutomateControl.setup_subparser(subparsers)
        HomeAssistantControl.setup_subparser(subparsers)

        args = parser.parse_args()

        await args.ctor().run(args)

    except Exception as e:
        logger.error(repr(e))

if __name__ == "__main__":
    # logger.setLevel(logging.DEBUG)
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
    exit(logger.exitcode)
