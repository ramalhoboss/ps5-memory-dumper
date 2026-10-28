"""Connection helpers: LAN discovery, connecting and best-effort console information."""
from ps5dbg import PS5Debug
from ps5dbg.constants import DEFAULT_PORT
from ps5dbg.discover import discover
from ps5dbg.errors import BadStatus, PS5DbgError

TIMEOUT = 10  # seconds per request


def discover_consoles(timeout=2.0):
    """IPs of the consoles that answer the ps5debug UDP broadcast (port 1010)."""
    return discover(timeout=timeout)


def connect(ip, port=DEFAULT_PORT, timeout=TIMEOUT):
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("Enter the PS5 IP address")
    ps5 = PS5Debug(ip, port=port, timeout=timeout)
    ps5.connect()
    return ps5


def firmware_text(value):
    """CMD_FW_VERSION answers a decimal such as 550 for 5.50."""
    return f"{value // 100}.{value % 100:02d}" if isinstance(value, int) else None


def console_info(ps5):
    """Every field is optional: older payloads do not implement all the commands.

    A refused command (BadStatus) only blanks its field. Any other failure may leave
    the stream out of sync, so the connection is reopened and the remaining
    queries are skipped.
    """
    info = dict(foreground=None, version=None, firmware=None, brand=None, capability=None)
    queries = (("foreground", ps5.foreground_app), ("version", ps5.version),
               ("firmware", lambda: firmware_text(ps5.fw_version())), ("brand", ps5.branding))
    for key, query in queries:
        try:
            info[key] = query()
        except BadStatus:
            continue
        except PS5DbgError:
            ps5.close()
            ps5.connect()
            break
    if info["brand"] is not None:
        info["brand"], info["capability"] = info["brand"].brand, info["brand"].capability_level
    return info


def process_details(ps5, pid):
    """Title id / content id / path for the manifest, or {} if the payload refuses."""
    if pid == 0:
        return {}
    try:
        detail = ps5.proc_info(pid)
    except BadStatus:
        return {}
    return {key: value for key, value in dict(path=detail.path, title_id=detail.titleid,
                                               content_id=detail.contentid).items() if value}
