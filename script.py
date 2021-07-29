"""
This small program consumes events by attaching to an interface processing HTTP
packets over it.

Every window-time, we compute the ratio of responses in errors (4xx, 5xx) as
well as the averaged latency over the window. Then we pushed these results to
Reliably as indicators.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import partial
import os
from pathlib import Path
from queue import Empty, Queue
import socket
import threading
import time
from typing import Dict

from bcc import BPF
import httpx
from pypacker import psocket
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer567 import http
import typer
import yaml

IFACE = "lo"
TARGET_PORT = 8000
WINDOW = 10
RELIABLY_HOST = "reliably.com"
RELIABLY_URL = f"https://api.{RELIABLY_HOST}/entities/<ORG>/reliably.com/v1/indicator"
RELIABLY_CONFIG_PATH = os.path.expanduser("~/.config/reliably/config.yaml")


class MySocketHndl(psocket.SocketHndl):
    def __init__(self, b: BPF, timeout: int = None, iface: str = IFACE):
        """
        BCC gives the us a socket to listen from. Bind to it.
        """
        function_http_filter = b.load_func("http_filter", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(function_http_filter, iface)
        socket_fd = function_http_filter.sock

        self._socket = socket.fromfd(
            socket_fd, socket.PF_PACKET, socket.SOCK_RAW,
            socket.IPPROTO_IP)

        # blocks forever when timeout is None
        self._socket.settimeout(timeout)


def filter_pkt(eth: ethernet.Ethernet, target_port: int = TARGET_PORT) -> bool:
    """
    Process only packets that are going to or from the target server.
    """
    if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
        tcp_p = eth[tcp.TCP]
        if tcp_p.dport == target_port or tcp_p.sport == target_port:
            return True
    return False


def make_key_from_tcp(packet: tcp.TCP, target_port: int = TARGET_PORT) -> str:
    """
    Creates a key from the source/dest address.
    """
    ip_p = packet[ip.IP]
    tcp_p = packet[tcp.TCP]
    if tcp_p.dport == target_port:
        return f"{ip_p.src_s}:{tcp_p.sport}|{ip_p.dst_s}:{tcp_p.dport}"
    return f"{ip_p.dst_s}:{tcp_p.dport}|{ip_p.src_s}:{tcp_p.sport}"


@contextmanager
def bpfsock(iface: str = IFACE):
    """
    Loads the BPF program and starts listening on the socket we attach
    to the interface. Cleanup when finished.
    """
    try:
        b = BPF(src_file = "ebpf.c")
        psock = MySocketHndl(b=b, iface=iface)
        yield psock
    finally:
        psock.close()
        b.cleanup()


def process_packets(requests: Queue, terminate: threading.Event,
                    iface: str = IFACE, port: int = TARGET_PORT) -> None:
    """
    Process ebpf packets as they we get them. We parse them to HTTP data
    and determine where we are in their lifecycle.

    This script makes the foundamental assumption that
    responses come in order of their requests with no interleaving. Indeed
    we have no signals to tell us otherwise.

    From the HTTP data, we simply keep what we need to create our indicators to
    send to Reliably.

    We do not wait to read the entire response body to measure the duration
    of the request/response exchange. So this trumps real latency but this
    is just a demo ;)
    """
    sessions = {}
    with bpfsock(iface=iface) as psock:
        for pkt in psock.recvp_iter(filter_match_recv=partial(
                filter_pkt, target_port=port)):
            key = make_key_from_tcp(pkt, port)
            h = http.HTTP(pkt[tcp.TCP].body_bytes)

            if key not in sessions:
                sessions[key] = {
                    "status": None,
                    "response_length": None,
                    "start": datetime.utcnow(),
                    "end": None,
                    "duration": 0,
                    "method": None,
                    "path": None,
                    "body": b""
                }

            if h.startline:
                l = h.startline.decode("utf-8")
                if l.startswith(("GET", "PUT", "POST", "DELETE", "HEAD")):
                    method, path, _ = l.split(" ", 2)
                    sessions[key]["path"] = path
                    sessions[key]["method"] = method
                elif l.startswith("HTTP"):
                    _, code, _ = l.split(" ", 2)
                    sessions[key]["status"] = int(code)

                    for hdr in h.hdr:
                        if b"content-length" == hdr[0]:
                            sessions[key]["response_length"] = int(hdr[1])
                            break
            else:
                sessions[key]["body"] = sessions[key]["body"] + h.body_bytes

                if sessions[key]["path"] and sessions[key]["method"] \
                        and sessions[key]["status"]:
                    sessions[key]["end"] = datetime.utcnow()
                    sessions[key]["duration"] = (sessions[key]["end"] -
                        sessions[key]["start"]).total_seconds()
                    
                    # ok we have a enough information now.
                    pt = sessions.pop(key, None)
                    requests.put(pt)

            # oh... did the user signal to terminate...?
            if terminate.is_set():
                break



def process_requests(requests: Queue, indicators: Queue, 
        terminate: threading.Event, push_window: int = WINDOW):
    """
    Compute the percentages of good latencies and good responses for a given
    window.
    """
    now = datetime.utcnow()
    last_push = now
    next_push = now + timedelta(seconds=push_window)
    requests_per_path = {}

    while not terminate.is_set():
        time.sleep(0.01)
        try:
            pt = requests.get_nowait()
            path = pt["path"]
            if path not in requests_per_path:
                requests_per_path[path] = []
            requests_per_path[path].append(pt)
        except Empty:
            continue

        now = datetime.utcnow()
        if now >= next_push:
            for path in requests_per_path:
                requests = requests_per_path[path]
                if not requests:
                    continue

                requests_per_path[path] = []
                total_count = class_2xx = good_latency_count = 0

                for pt in requests:
                    if last_push <= pt["end"] < next_push:
                        total_count += 1
                        # our SLO latency is 150ms
                        if pt["duration"] <= 0.15:
                            good_latency_count += 1
                        if pt["status"] == 200:
                            class_2xx += 1

                if total_count == 0:
                    continue

                indicators.put(
                    (
                        "availability", last_push, next_push, path,
                        100.0 * (class_2xx / total_count)
                    )
                )
                indicators.put(
                    (
                        "latency", last_push, next_push, path,
                        100.0 * (good_latency_count / total_count)
                    )
                )

            # reset for next window
            last_push = next_push
            next_push = next_push + timedelta(seconds=push_window)


def update_slo(indicators: Queue, terminate: threading.Event, reliably_config: Path):
    """
    Turning requests/response data into Reliably indicators and sending them
    to the Reliably's endpoint.
    """
    info = extract_reliably_info(reliably_config)
    reliably_url = RELIABLY_URL.replace("<ORG>", info["org_name"])

    while not terminate.is_set():
        time.sleep(0.01)
        try:
            indicator_type, from_ts, to_ts, path, value = indicators.get_nowait()
        except Empty:
            continue

        headers = {
            "Authorization": f"Bearer {info['token']}"
        }
        indicator = {
            "metadata": {
                "labels": {
                    "category": indicator_type,
                    "path": path
                }
            },
            "spec": {
                "from": f"{from_ts.isoformat()}Z",
                "to": f"{to_ts.isoformat()}Z",
                "percent": value
            }
        }

        if indicator_type == "latency":
            indicator["metadata"]["labels"]["percentile"] = "100"
            indicator["metadata"]["labels"]["latency_target"] = "150ms"

        r = httpx.put(reliably_url, headers=headers, json=indicator)
        if r.status_code > 399:
            type.echo(
                f"Failed to push indicators to Reliably: {r.text}", err=True)


def extract_reliably_info(reliably_config: Path) -> Dict[str, str]:
    """
    Retrieve the orgname and token of the user from the Reliably's config
    """
    with open(reliably_config) as f:
        config = yaml.safe_load(f)
        current_org_name = config["currentOrg"]["name"]
        for host in config["auths"]:
            if host == RELIABLY_HOST:
                info = config["auths"][host].copy()
                info["org_name"] = current_org_name
                return info


def run(reliably_config: Path = typer.Option(RELIABLY_CONFIG_PATH),
        push_window: int = typer.Option(WINDOW, help="How often will we push our indicators"),
        interface: str = typer.Option(IFACE, help="Network interface to listen to"),
        target_port: int = typer.Option(TARGET_PORT, help="Port of the HTTP server to parse requests")):
    requests = Queue()
    indicators = Queue()
    terminate = threading.Event()

    packet_loop = threading.Thread(
        None, process_packets, args=(requests, terminate, interface, target_port))
    packet_loop.start()

    process_loop = threading.Thread(
        None, process_requests, args=(requests, indicators, terminate, push_window))
    process_loop.start()

    slo_loop = threading.Thread(
        None, update_slo, args=(indicators, terminate, reliably_config))
    slo_loop.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        terminate.set()
    finally:
        packet_loop.join()
        process_loop.join()
        slo_loop.join()


if __name__ == "__main__":
    typer.run(run)
