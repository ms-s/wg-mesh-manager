import json
import logging
import os
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from threading import Lock
from time import time
from typing import Any, Dict, List, Optional
from secrets import token_urlsafe
from netaddr import IPNetwork, IPAddress

import yaml

logger = logging.getLogger(__name__)

TOKEN_LIFETIME_MINUTES = 60
MANAGER_LOCK = Lock()


@dataclass
class Config:
    # API key
    api_key: str

    # Private IP address range for WireGuard IPs from, e.g. "10.0.0.0/8"
    subnet: str
    # Prefix length for individual overlay subnet, e.g., 24 for "10.0.0.0/24"
    overlay_prefix_len: int

    # Path to the state file. This should be protected and only writablle by the service
    state_path: str

    @classmethod
    def from_yaml(cls, filename: str) -> "Config":
        conf = yaml.safe_load(open(filename, encoding='utf-8'))
        if conf is None:
            logger.error(f"Config at {0} is empty.".format(filename))
            raise RuntimeError(f"Config at {filename} is empty.")
        return cls(**conf)

    @classmethod
    def from_env(cls) -> "Config":
        """
        Build a config object from environment variables
        """
        for env_var in ("API_KEY", "MESHMASH_SUBNET", "MESHMASH_STATE_PATH"):
            if env_var not in os.environ:
                logger.error(f"Missing environment variable: {0}".format(env_var))
                raise RuntimeError(f"Missing environment variable: {env_var}")

        return cls(
            api_key=os.environ["API_KEY"],
            subnet="10.0.0.0/8",
            overlay_prefix_len=24,
            state_path=os.environ["MESHMASH_STATE_PATH"]
        )


@dataclass
class Device:
    device_id: str
    device_name: str
    hostname: str
    public_ip: str
    public_key: str
    listen_port: int
    token: str  # TODO: allow two overlapping tokens
    expiry_ts: float


@dataclass
class Overlay:
    overlay_id: str
    overlay_name: str
    subnet: str
    devices: Dict[str,str]

    def __init__(self, overlay_id, overlay_name, subnet, devices):
        self.overlay_id = overlay_id
        self.subnet = subnet
        self.overlay_name = overlay_name
        self.devices = devices


@dataclass
class Manager:
    config: Config
    devices: Dict[str, Device] = field(default_factory=dict)
    overlays: Dict[str, Overlay] = field(default_factory=dict)


    def load_state(self) -> None:
        logger.info(f"Loading state from {0}".format(self.config.state_path))
        with MANAGER_LOCK:
            if os.path.exists(self.config.state_path):
                state = json.load(open(self.config.state_path, encoding='utf-8'))
                logger.debug(f"Loaded state: {0}".format(state))

                for device_dict in state.get("devices", []):
                    device = Device(**device_dict)
                    self.devices[device.device_id] = device

                for overlay_dict in state.get("overlays", []):
                    overlay = Overlay(**overlay_dict)
                    self.overlays[overlay.overlay_id] = overlay


    def save_state(self) -> None:
        logger.info(f"Saving state to {0}".format(self.config.state_path))
        bkup_file = self.config.state_path + ".bkup"
        do_backup = os.path.exists(self.config.state_path)

        with MANAGER_LOCK:
            if do_backup:
                shutil.copyfile(self.config.state_path, bkup_file)
                os.chmod(bkup_file, 0o600)
            try:
                state: Dict[str, List[Any]] = {"overlays": [], "devices": []}
                for device in self.devices.values():
                    state["devices"].append(asdict(device))
                for overlay in self.overlays.values():
                    state["overlays"].append(asdict(overlay))

                with open(self.config.state_path, "w", encoding='utf-8') as file:
                    file.write(json.dumps(state))
                os.chmod(self.config.state_path, 0o600)
            except:
                # Restore the backup and re-raise the exception
                if do_backup:
                    os.rename(bkup_file, self.config.state_path)
                raise


    def api_key_is_valid(self, api_key: str) -> bool:
        return bool(api_key and api_key == self.config.api_key)


    def device_token_is_valid(self, device_id: str, device_token: str) -> str:
        if device_id not in self.devices:
            return "Device id for token lookup not found"
        if device_token == self.devices[device_id].token:
            if time() < self.devices[device_id].expiry_ts:
                return "Valid"
            return "Token expired"
        return "Wrong token"


    def get_fresh_token(self, device_id: str) -> str:
        with MANAGER_LOCK:
            if device_id not in self.devices:
                return json.dumps({"error": "Device id not found"})
            self.devices[device_id].token = token_urlsafe(16)
            self.devices[device_id].expiry_ts = time() + 60 * TOKEN_LIFETIME_MINUTES
            return json.dumps(self.devices[device_id].__dict__)



    def create_overlay(self, overlay_name: str) -> str:
        with MANAGER_LOCK:
            overlay_id = uuid.uuid4().hex
            subnet: Optional[IPNetwork]
            for subnet in IPNetwork(self.config.subnet).subnet(self.config.overlay_prefix_len):
                if all(str(subnet) != overlay.subnet for overlay in self.overlays.values()):
                    break
            else:
                return json.dumps({"error": "Exhausted overlay subnets"})
            overlay = Overlay(overlay_id, overlay_name, str(subnet), {})
            self.overlays[overlay_id] = overlay
            return json.dumps(overlay.__dict__)


    def delete_overlay_id(self, overlay_id: str) -> str:
        if overlay_id not in self.overlays:
            return json.dumps({"error": "Overlay id not found"})
        self.overlays.pop(overlay_id)
        return json.dumps({"status": "Deleted"})


    def get_overlays_list(self) -> str:
        return json.dumps({'overlays': list(self.overlays.keys())})


    def get_devices_list(self) -> str:
        return json.dumps({'devices': list(self.devices.keys())})


    def get_overlay_info(self, overlay_id: str) -> str:
        if overlay_id not in self.overlays:
            return json.dumps({"error": "Overlay id not found"})
        return json.dumps(self.overlays[overlay_id].__dict__)


    def get_device_info(self, device_id: str) -> str:
        if device_id not in self.devices:
            return json.dumps({"error": "Device id not found"})
        return json.dumps(self.devices[device_id].__dict__)


    def create_device(self, hostname: str, device_name: str, public_ip: str, public_key: str, listen_port: int) -> str:
        with MANAGER_LOCK:
            dev_id = uuid.uuid4().hex
            device = Device(dev_id, device_name, hostname, public_ip, public_key, listen_port, \
                token_urlsafe(16), time()+60 * TOKEN_LIFETIME_MINUTES)
            self.devices[dev_id] = device
            return json.dumps(device.__dict__)


    def delete_device_id(self, device_id: str) -> str:
        with MANAGER_LOCK:
            if device_id not in self.devices:
                return json.dumps({"error": "Device id not found"})
            for overlay in self.overlays.values():  # also delete from any overlay
                if device_id in overlay.devices:
                    overlay.devices.pop(device_id)
            self.devices.pop(device_id) # delete from devices
            return json.dumps({"status": "Deleted"})


    def remove_device_from_overlay(self, overlay_id: str, device_id: str) -> str:
        with MANAGER_LOCK:
            if overlay_id not in self.overlays:
                return json.dumps({"error": "Overlay id not found"})
            if device_id not in self.overlays[overlay_id].devices:
                return json.dumps({"error": "Device not in overlay"})
            self.overlays[overlay_id].devices.pop(device_id)
            return json.dumps({"status": "Device removed"})


    def wgconfig(self, overlay_id: str, device_id: str) -> str:
        wg_conf = ""
        i=0
        if overlay_id not in self.overlays:
            return json.dumps({"error": "Overlay id not found"})
        overlay = self.overlays[overlay_id]
        if device_id not in overlay.devices:
            return json.dumps({"error": "Device not in overlay"})
        for device in overlay.devices:
            if device != device_id:
                i += 1
                wg_conf += f"[Peer {i}]\n" \
                f"PublicKey = {self.devices[device].public_key}\n" \
                f"AllowedIPs = {overlay.devices[device]}/32\n" \
                f"Endpoint = {self.devices[device].public_ip}: {self.devices[device].listen_port}\n\n"
        return wg_conf


    def next_available_ip(self, overlay_id: str) -> str:
        """
        Get the next available private IP
        """
        overlay = self.overlays[overlay_id]
        addresses = iter(IPNetwork(overlay.subnet))
        next(addresses)
        addr: Optional[IPAddress]
        for addr in addresses:
            if all(str(addr) != existing_addr for existing_addr in overlay.devices.values()):
                break
        else:
            return json.dumps({"error":
                f"Exhausted IP addresses in the overlay subnet {overlay.subnet}"})
        return str(addr)


    def add_device_to_overlay(self, overlay_id: str, device_id: str) -> str:
        with MANAGER_LOCK:
            if overlay_id not in self.overlays:
                return json.dumps({"error": "Overlay id not found"})
            if device_id not in self.devices:
                return json.dumps({"error": "Device id not found"})
            if device_id in self.overlays[overlay_id].devices.keys():
                return json.dumps({"error": "Device already in overlay"})
            self.overlays[overlay_id].devices[device_id] = self.next_available_ip(overlay_id)
            return json.dumps({"status": "Device added","tunnel_ip":self.overlays[overlay_id].devices[device_id]})
