from typing import Any, Optional, Union, Tuple, Dict
from flask import Flask, Request, g, request, jsonify
# from flask import Flask, Request, g, request
from meshmash.manager import Config, Manager, Device

app = Flask(__name__)


@app.route("/overlays", methods=["GET"])
def get_overlays() -> Union[str, Tuple[str, int]]:
    """
    Get list of overlays.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        if len(manager.overlays) > 0:
            return manager.get_overlays_list()
        return jsonify(error="No overlays created; use POST to create overlays")
    return jsonify(error="Not authorized"), 403


@app.route("/devices", methods=["GET"])
def get_devices() -> Union[str, Tuple[str, int]]:
    """
    Get list of devices.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        if len(manager.devices) > 0:
            return manager.get_devices_list()
        return jsonify(error="No devices created; use POST to create devices")
    return jsonify(error="Not authorized"), 403


@app.route("/overlays/<overlay_id>", methods=["DELETE"])
def delete_overlay(overlay_id) -> Union[str, Tuple[str, int]]:
    """
    Delete overlay with given overlay id.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        return manager.delete_overlay_id(overlay_id)
    return jsonify(error="Not authorized"), 403


@app.route("/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id) -> Union[str, Tuple[str, int]]:
    """
    Delete device with given id.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        return manager.delete_device_id(device_id)
    return jsonify(error="Not authorized"), 403


@app.route("/devices/<device_id>", methods=["PUT"])
def put_device(device_id) -> Union[str, Tuple[str, int]]:
    """
    Update device info.
    """
    manager = get_manager()
    token_status = ""
    api_key_valid = False
    if "Authorization" in request.headers :
        token_status = manager.device_token_is_valid(device_id, header_token(request))
        if token_status != "Valid":
            return jsonify(error="Not authorized: "+token_status), 403
    elif "X-Api-Key" in request.headers:
        api_key = header_api_key(request)
        api_key_valid = manager.api_key_is_valid(api_key)
        if not api_key_valid:
            return jsonify(error="Not authorized"), 403
    if token_status == 'Valid' or api_key_valid:
        if request.data:
            device: Device
            for device in manager.devices:
                if device == device_id:
                    if "hostname" in request.get_json():
                        for device2 in manager.devices:
                            if device != device2 and \
                                request.get_json()['hostname'] == manager.devices[device2].hostname:
                                return jsonify(error="Hostname used by existing device")
                        manager.devices[device].hostname = request.get_json()['hostname']
                    if "public_key" in request.get_json():
                        manager.devices[device].public_key = request.get_json()['public_key']
                    # TODO: check that the same IP and port are not used by two devices
                    if "public_ip" in request.get_json():
                        manager.devices[device].public_ip = request.get_json()['public_ip']
                    if "listen_port" in request.get_json():
                        manager.devices[device].listen_port = request.get_json()['listen_port']
                    return manager.get_device_info(device_id)
            return jsonify(error="Device ID not found")
        return jsonify(error="Add updated device data to body"), 400
    return jsonify(error="Not authorized"), 403


@app.route("/overlays/<overlay_id>", methods=["GET"])
def get_overlay(overlay_id) -> Union[str, Tuple[str, int]]:
    """
    Get overlay info.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        return manager.get_overlay_info(overlay_id)
    return jsonify(error="Not authorized"), 403


@app.route("/devices/<device_id>", methods=["GET"])
def get_device(device_id) -> Union[str, Tuple[str, int]]:
    """
    Get device info.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        return manager.get_device_info(device_id)
    return jsonify(error="Not authorized"), 403


@app.route("/overlays", methods=["POST"])
def post_overlay() -> Union[str, Tuple[str, int]]:
    """
    Create a new overlay.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if not manager.api_key_is_valid(api_key):
        return jsonify(error="Not authorized"), 403
    if not request.data:
        return jsonify(error="Send a human friendly name for overlay in body"), 400
    if "overlay_name" not in request.json:
        return jsonify(error="Send overlay_name for overlay"), 400
    if request.get_json()['overlay_name'] == "":        
        return jsonify(error="overlay_name cannot be empty"), 400
    if any(request.get_json()['overlay_name'] == str(overlay.overlay_name) for overlay in manager.overlays.values()):
        return jsonify(error="Overlay_name used by existing overlay"), 400
    return manager.create_overlay(request.get_json()['overlay_name'])
            
        
    


@app.route("/devices", methods=["POST"])
def post_device() -> Union[str, Tuple[str, int]]:
    """
    Create a new device.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if not manager.api_key_is_valid(api_key):
        return jsonify(error="Not authorized"), 403
    if not request.data:
        return jsonify(error="No device data in POST"), 400
    for field in ("hostname", "public_ip", "public_key", "listen_port", "device_name"):
        if field not in request.json:
            return jsonify(error="Missing data field (public_ip, public_key, and listen_port can be left empty but should be present in request): "+field), 400
    if request.get_json()['hostname'] == "" or request.get_json()['device_name'] == "":
        return jsonify(error="Device hostname or device name cannot be empty"), 400
    if any((request.get_json()['device_name'] == str(device.device_name) or request.get_json()['device_name'] == str(device.hostname)) for device in manager.devices.values()):
        return jsonify(error="Device hostname or device name used by existing device"), 400
    return manager.create_device(**request.get_json())


@app.route("/overlays/<overlay_id>/devices", methods=["POST"])
def add_device(overlay_id) -> Union[str, Tuple[str, int]]:
    """
    Add device to an overlay.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if not manager.api_key_is_valid(api_key):
        return jsonify(error="Not authorized"), 403
    if not request.data:
        return jsonify(error="Send device id to add to overlay in body"), 400
    if "device_id" in request.json:
        return manager.add_device_to_overlay(overlay_id,request.get_json()['device_id'])
    return jsonify(error="Send device_id as JSON"), 400


@app.route("/overlays/<overlay_id>/devices/<string:device_id>/wgconfig", methods=["GET"])
def wgconfig(overlay_id, device_id) -> Union[str, Tuple[str, int]]:
    """
    Get wireguard config.
    """
    manager = get_manager()
    token_status = manager.device_token_is_valid(device_id, header_token(request))
    if token_status == "Valid":
        return manager.wgconfig(overlay_id, device_id)
    return jsonify(error="Not authorized: "+token_status), 403


@app.route("/devices/<string:device_id>/token", methods=["GET"])
def get_token(device_id) -> Union[str, Tuple[str, int]]:
    """
    Get wireguard config.
    """
    manager = get_manager()
    if "Authorization" in request.headers:
        token_status = manager.device_token_is_valid(device_id, header_token(request))
        if token_status == "Valid":
            return manager.get_fresh_token(device_id)
        return jsonify(error="Not authorized: "+token_status), 403
    if "X-Api-Key" in request.headers:
        api_key = header_api_key(request)
        if manager.api_key_is_valid(api_key):
            return manager.get_fresh_token(device_id)
    return jsonify(error="Not authorized"), 403


@app.route("/overlays/<overlay_id>/devices/<string:device_id>", methods=["DELETE"])
def remove_device(overlay_id, device_id) -> Union[str, Tuple[str, int]]:
    """
    Remove device from an overlay.
    """
    manager = get_manager()
    api_key = header_api_key(request)
    if manager.api_key_is_valid(api_key):
        return manager.remove_device_from_overlay(overlay_id,device_id)
    return jsonify(error="Not authorized"), 403


def get_manager() -> Manager:
    if "manager" not in g:
        app.logger.info("Creating Manager")
        g.manager = Manager(Config.from_env())
        g.manager.load_state()
    assert isinstance(g.manager, Manager)
    return g.manager


@app.teardown_appcontext
def teardown_manager(*args: Any) -> None:
    app.logger.info("Tearing down Manager")
    manager = g.pop("manager", None)
    if manager is not None:
        manager.save_state()


def header_api_key(req: Request) -> Optional[str]:
    """
    Get the api key from a request.headers object
    """
    return req.headers.get("X-Api-Key")


def header_token(req: Request) -> Optional[str]:
    """
    Get the token from a request.headers object
    """
    value = req.headers.get("Authorization", "")
    if value is not None and value.startswith("Bearer "):
        return value.replace("Bearer ", "")
    return None
