from __future__ import annotations

import collections
import queue
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .analyzer import _extract_l3_context
from .utils import DetectionPacket

AlertCallback = Callable[[dict[str, Any]], None]


@dataclass
class LiveConfig:
    """Configuration for the producer-consumer live engine."""

    interface: str | None = None
    count: int = 0  # 0 = unlimited (runs until timeout or stop)
    timeout: float | None = 30  # None = no timeout
    bpf_filter: str = ""
    queue_maxsize: int = 10000
    packet_output_limit: int = 5000

    # Detection thresholds (mirrors detections.py constants)
    syn_scan_window: float = 10.0
    syn_scan_threshold: int = 15
    udp_scan_window: float = 10.0
    udp_scan_threshold: int = 15
    icmp_sweep_window: float = 5.0
    icmp_sweep_threshold: int = 5
    dns_exfil_window: float = 60.0
    dns_exfil_threshold: int = 200
    icmp_flood_threshold: float = 100.0
    syn_flood_threshold: float = 200.0
    beacon_min_samples: int = 6
    beacon_cov_threshold: float = 0.15


class SlidingWindowTracker:
    """Thread-safe tracker maintaining a set of unique keys over a sliding
    time window."""

    def __init__(self, window_sec: float) -> None:
        self._window = window_sec
        self._lock = threading.Lock()
        self._items: collections.deque[tuple[float, Any]] = collections.deque()

    def add(self, timestamp: float, key: Any) -> None:
        with self._lock:
            self._items.append((timestamp, key))
            self._prune(timestamp)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()

    def prune(self, now: float | None = None) -> None:
        with self._lock:
            self._prune(now or time.time())

    def unique_keys(self, now: float | None = None) -> set[Any]:
        with self._lock:
            self._prune(now or time.time())
            return {k for _, k in self._items}

    def unique_count(self, now: float | None = None) -> int:
        with self._lock:
            self._prune(now or time.time())
            return len({k for _, k in self._items})

    def item_count(self, now: float | None = None) -> int:
        with self._lock:
            self._prune(now or time.time())
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class RateTracker:
    """Track event rate over a 1-second sliding window using a deque of
    timestamps."""

    def __init__(self, window_sec: float = 1.0) -> None:
        self._window = window_sec
        self._lock = threading.Lock()
        self._times: collections.deque[float] = collections.deque()

    def tick(self, timestamp: float | None = None) -> None:
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            self._times.append(now)
            self._prune(now)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._times and self._times[0] < cutoff:
            self._times.popleft()

    def rate(self, now: float | None = None) -> float:
        with self._lock:
            ts = now or time.time()
            self._prune(ts)
            return len(self._times) / self._window

    def clear(self) -> None:
        with self._lock:
            self._times.clear()


class TTLDict:
    """Dict that auto-expires entries not touched within *ttl_sec* seconds."""

    def __init__(self, ttl_sec: float = 300.0) -> None:
        self._ttl = ttl_sec
        self._lock = threading.Lock()
        self._data: dict[Any, Any] = {}
        self._touched: dict[Any, float] = {}

    def __getitem__(self, key: Any) -> Any:
        with self._lock:
            val = self._data[key]
            self._touched[key] = time.time()
            return val

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            if key in self._data:
                self._touched[key] = time.time()
                return self._data[key]
            return default

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = value
            self._touched[key] = time.time()

    def setdefault(self, key: Any, default: Any) -> Any:
        with self._lock:
            if key not in self._data:
                self._data[key] = default
                self._touched[key] = time.time()
            return self._data[key]

    def prune(self, now: float | None = None) -> int:
        ts = now or time.time()
        cutoff = ts - self._ttl
        with self._lock:
            expired = [k for k, t in self._touched.items() if t < cutoff]
            for k in expired:
                del self._data[k]
                del self._touched[k]
            return len(expired)

    def items(self) -> list[tuple[Any, Any]]:
        with self._lock:
            return list(self._data.items())

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class OnlineStats:
    """Welford's online algorithm for streaming mean/variance computation.

    Used by beaconing detection to calculate CoV incrementally.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0

    def add(self, value: float) -> None:
        with self._lock:
            self._count += 1
            delta = value - self._mean
            self._mean += delta / self._count
            delta2 = value - self._mean
            self._m2 += delta * delta2

    @property
    def count(self) -> int:
        return self._count

    @property
    def mean(self) -> float:
        with self._lock:
            return self._mean

    @property
    def variance(self) -> float:
        with self._lock:
            return self._m2 / self._count if self._count > 1 else 0.0

    @property
    def stdev(self) -> float:
        return self.variance ** 0.5

    @property
    def cov(self) -> float:
        m = self.mean
        return self.stdev / m if m != 0 else float("inf")


def _detect_link_type(pkt: Any) -> int:
    """Detect the link-layer type from a scapy packet object.

    Returns one of the LINKTYPE_* constants (1=Ethernet, 0=NULL/loopback,
    113=Linux SLL/cooked, 101=raw IP).  Defaults to 1 (Ethernet).
    """
    name = type(pkt).__name__
    if name == "Ether":
        return 1
    if name in ("SLL", "CookedLinux"):
        return 113
    if name in ("Loopback", "IPnull"):
        return 0
    if name == "IP":
        return 101
    return 1


def _parse_raw_packet(
    arrival_ts: float,
    raw: bytes,
    link_type: int = 1,
) -> DetectionPacket | None:
    """Parse a single raw frame into a DetectionPacket.

    Minimal parser — extracts only fields needed by incremental live rules:
    src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, icmp_type.
    """
    l2, l3_offset, eth_type = _extract_l3_context(raw, link_type)
    if l3_offset is None or eth_type is None:
        return None

    while eth_type in (0x8100, 0x88A8) and len(raw) >= l3_offset + 4:
        eth_type = struct.unpack(">H", raw[l3_offset + 2 : l3_offset + 4])[0]
        l3_offset += 4

    dst_ip: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    l4: str | None = None
    ttl: int | None = None
    tcp_flags: list[str] = []
    icmp_type: int | None = None

    if eth_type == 0x0800 and len(raw) >= l3_offset + 20:
        ihl = (raw[l3_offset] & 0x0F) * 4
        ip_hdr_end = l3_offset + ihl
        if ihl >= 20 and len(raw) >= ip_hdr_end:
            proto = raw[l3_offset + 9]
            ttl = raw[l3_offset + 8]
            src_ip = ".".join(str(b) for b in raw[l3_offset + 12 : l3_offset + 16])
            dst_ip = ".".join(str(b) for b in raw[l3_offset + 16 : l3_offset + 20])

            if proto == 6 and len(raw) >= ip_hdr_end + 20:
                l4 = "TCP"
                src_port = struct.unpack(">H", raw[ip_hdr_end : ip_hdr_end + 2])[0]
                dst_port = struct.unpack(">H", raw[ip_hdr_end + 2 : ip_hdr_end + 4])[0]
                flags_byte = raw[ip_hdr_end + 13]
                tcp_flags = _decode_tcp_flags(flags_byte)

            elif proto == 17 and len(raw) >= ip_hdr_end + 8:
                l4 = "UDP"
                src_port = struct.unpack(">H", raw[ip_hdr_end : ip_hdr_end + 2])[0]
                dst_port = struct.unpack(">H", raw[ip_hdr_end + 2 : ip_hdr_end + 4])[0]

            elif proto == 1 and len(raw) >= ip_hdr_end + 4:
                l4 = "ICMP"
                icmp_type = raw[ip_hdr_end]

    elif eth_type == 0x0806:
        l4 = "ARP"

    return DetectionPacket(
        index=0,
        timestamp=arrival_ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=l4 or "UNKNOWN",
        length=len(raw),
        ttl=ttl,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
    )


_FLAG_LOOKUP: dict[int, str] = {
    0x02: "SYN", 0x10: "ACK", 0x01: "FIN", 0x04: "RST",
    0x08: "PSH", 0x20: "URG",
}


def _decode_tcp_flags(flags_byte: int) -> list[str]:
    result: list[str] = []
    for mask, name in _FLAG_LOOKUP.items():
        if flags_byte & mask:
            result.append(name)
    return result


class LiveEngine:
    """Producer-consumer live capture engine.

    Usage::

        engine = LiveEngine(
            config=LiveConfig(interface="eth0", bpf_filter="tcp or udp"),
            on_alert=lambda a: print(json.dumps(a)),
        )
        engine.start()
        time.sleep(30)
        engine.stop()
        print(engine.stats())
    """

    def __init__(
        self,
        config: LiveConfig,
        on_alert: AlertCallback | None = None,
    ) -> None:
        self.config = config
        self.on_alert = on_alert
        self._queue: queue.Queue[tuple[float, int, bytes] | None] = queue.Queue(
            maxsize=config.queue_maxsize
        )
        self._link_type: int = 1  # LINKTYPE_ETHERNET (default, will be detected from first packet)
        self._stop = threading.Event()
        self._producer: threading.Thread | None = None
        self._consumer: threading.Thread | None = None
        self._start_ts: float = 0.0
        self._packets_consumed: int = 0
        self._alerts_emitted: int = 0
        self._consumer_errors: int = 0

        # Sliding-window state per rule
        self.syn_scan: dict[tuple[str, str], SlidingWindowTracker] = {}
        self.syn_scan_lock = threading.Lock()
        self.udp_scan: dict[tuple[str, str], SlidingWindowTracker] = {}
        self.udp_scan_lock = threading.Lock()
        self.icmp_sweep: dict[str, SlidingWindowTracker] = {}
        self.icmp_sweep_lock = threading.Lock()
        self.dns_exfil: dict[tuple[str, str], SlidingWindowTracker] = {}
        self.dns_exfil_lock = threading.Lock()
        self.icmp_flood: dict[tuple[str, str], RateTracker] = {}
        self.icmp_flood_lock = threading.Lock()
        self.syn_flood: dict[tuple[str, str], RateTracker] = {}
        self.syn_flood_lock = threading.Lock()
        # Beaconing: stores (prev_ts, OnlineStats) per (src_ip, dst_ip)
        self.beaconing: dict[tuple[str, str], tuple[float, OnlineStats]] = {}
        self.beaconing_lock = threading.Lock()
        self.arp_spoofing: TTLDict = TTLDict(ttl_sec=300.0)
        # Cooldown: avoid duplicate alerts for the same rule+src+dst
        self._alert_cooldown: TTLDict = TTLDict(ttl_sec=60.0)

    def start(self) -> None:
        """Start the producer and consumer threads."""
        self._start_ts = time.time()
        self._stop.clear()

        self._producer = threading.Thread(
            target=self._producer_loop,
            name="live-producer",
            daemon=True,
        )
        self._consumer = threading.Thread(
            target=self._consumer_loop,
            name="live-consumer",
            daemon=True,
        )
        self._producer.start()
        self._consumer.start()

    def stop(self) -> dict[str, Any]:
        """Signal all threads to stop and return capture stats."""
        self._stop.set()
        while True:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                continue
            break
        if self._producer and self._producer.is_alive():
            self._producer.join(timeout=3)
        if self._consumer and self._consumer.is_alive():
            self._consumer.join(timeout=3)
        return self.stats()

    def stats(self) -> dict[str, Any]:
        elapsed = time.time() - self._start_ts if self._start_ts else 0.0
        return {
            "uptime_sec": round(elapsed, 3),
            "packets_consumed": self._packets_consumed,
            "alerts_emitted": self._alerts_emitted,
            "consumer_errors": self._consumer_errors,
            "packets_per_sec": (
                round(self._packets_consumed / elapsed, 1) if elapsed > 0 else 0.0
            ),
            "queue_size": self._queue.qsize(),
        }

    def _producer_loop(self) -> None:
        """Ingest packets from NIC as fast as possible and enqueue raw bytes."""
        scapy = self._import_scapy()

        _lt_store: list[int] = []

        def _enqueue(pkt: Any) -> None:
            if not _lt_store:
                _lt_store.append(_detect_link_type(pkt))
            try:
                self._queue.put_nowait(
                    (time.time(), _lt_store[0], bytes(pkt))
                )
            except queue.Full:
                pass

        try:
            scapy.sniff(
                iface=self.config.interface,
                prn=_enqueue,
                store=False,
                filter=self.config.bpf_filter or None,
                count=self.config.count if self.config.count > 0 else None,
                timeout=self.config.timeout,
            )
        except PermissionError:
            import sys
            print(
                "[live-engine] Permission denied: live capture requires root. "
                "Run with: sudo python3 packet_analyzer.py --live",
                file=sys.stderr,
            )
            self._queue.put_nowait(None)
        except Exception as exc:
            import sys
            print(f"[live-engine] Producer error: {exc}", file=sys.stderr)
            self._queue.put_nowait(None)

    def _consumer_loop(self) -> None:
        """Pull packets from the queue, parse, and run incremental rules."""
        prune_counter = 0
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue

            if item is None:
                break

            arrival_ts, link_type, raw = item
            pkt = _parse_raw_packet(arrival_ts, raw, link_type)
            if pkt is None:
                continue

            self._packets_consumed += 1
            self._run_incremental_rules(pkt)

            prune_counter += 1
            if prune_counter >= 100:
                prune_counter = 0
                self._periodic_prune()

    def _run_incremental_rules(self, pkt: DetectionPacket) -> None:
        """Evaluate all incremental detection rules against one packet."""
        ts = pkt.get("timestamp") or time.time()
        proto = pkt.get("protocol", "")
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        dport = pkt.get("dst_port")
        flags = pkt.get("tcp_flags") or []

        if proto == "TCP" and src and dst and dport is not None:
            if "SYN" in flags and "ACK" not in flags:
                key = (src, dst)
                with self.syn_scan_lock:
                    if key not in self.syn_scan:
                        self.syn_scan[key] = SlidingWindowTracker(
                            self.config.syn_scan_window
                        )
                    tracker = self.syn_scan[key]
                    tracker.add(ts, dport)
                    if tracker.unique_count(ts) >= self.config.syn_scan_threshold:
                        ports = sorted(tracker.unique_keys(ts))
                        tracker.clear()
                        self._emit({
                            "rule": "detect_tcp_syn_scan",
                            "severity": "HIGH",
                            "src_ip": src,
                            "dst_ip": dst,
                            "timestamp": ts,
                            "protocol": "TCP",
                            "description": (
                                f"{src} sent SYN-only packets to "
                                f"{len(ports)} ports on {dst} within "
                                f"{self.config.syn_scan_window}s"
                            ),
                            "evidence": {
                                "ports": ports,
                                "window_seconds": self.config.syn_scan_window,
                            },
                            "tags": ["recon", "scan"],
                        })

        if proto == "UDP" and src and dst and dport is not None:
            key = (src, dst)
            with self.udp_scan_lock:
                if key not in self.udp_scan:
                    self.udp_scan[key] = SlidingWindowTracker(
                        self.config.udp_scan_window
                    )
                tracker = self.udp_scan[key]
                tracker.add(ts, dport)
                if tracker.unique_count(ts) >= self.config.udp_scan_threshold:
                    ports = sorted(tracker.unique_keys(ts))
                    tracker.clear()
                    self._emit({
                        "rule": "detect_udp_scan",
                        "severity": "HIGH",
                        "src_ip": src,
                        "dst_ip": dst,
                        "timestamp": ts,
                        "protocol": "UDP",
                        "description": (
                            f"{src} sent UDP packets to "
                            f"{len(ports)} ports on {dst} within "
                            f"{self.config.udp_scan_window}s"
                        ),
                        "evidence": {
                            "ports": ports,
                            "window_seconds": self.config.udp_scan_window,
                        },
                        "tags": ["recon", "scan"],
                    })

        if proto == "ICMP" and src and pkt.get("icmp_type") == 8:
            with self.icmp_sweep_lock:
                if src not in self.icmp_sweep:
                    self.icmp_sweep[src] = SlidingWindowTracker(
                        self.config.icmp_sweep_window
                    )
                tracker = self.icmp_sweep[src]
                if dst:
                    tracker.add(ts, dst)
                    if (
                        tracker.unique_count(ts)
                        >= self.config.icmp_sweep_threshold
                    ):
                        targets = sorted(tracker.unique_keys(ts))
                        tracker.clear()
                        self._emit({
                            "rule": "detect_icmp_sweep",
                            "severity": "HIGH",
                            "src_ip": src,
                            "timestamp": ts,
                            "protocol": "ICMP",
                            "description": (
                                f"{src} sent ICMP echo requests to "
                                f"{len(targets)} hosts within "
                                f"{self.config.icmp_sweep_window}s"
                            ),
                            "evidence": {
                                "targets": targets,
                                "window_seconds": self.config.icmp_sweep_window,
                            },
                            "tags": ["recon"],
                        })

        if proto == "ICMP" and src and dst and pkt.get("icmp_type") == 8:
            key = (src, dst)
            with self.icmp_flood_lock:
                if key not in self.icmp_flood:
                    self.icmp_flood[key] = RateTracker(window_sec=1.0)
                rt = self.icmp_flood[key]
                rt.tick(ts)
                if rt.rate(ts) >= self.config.icmp_flood_threshold:
                    rt.clear()
                    self._emit({
                        "rule": "detect_icmp_flood",
                        "severity": "HIGH",
                        "src_ip": src,
                        "dst_ip": dst,
                        "timestamp": ts,
                        "protocol": "ICMP",
                        "description": f"ICMP echo request flood from {src} to {dst}",
                        "evidence": {
                            "rate_pps": rt.rate(ts),
                            "threshold_pps": self.config.icmp_flood_threshold,
                        },
                        "tags": ["dos"],
                    })

        if proto == "TCP" and src and dst:
            if "SYN" in flags and "ACK" not in flags:
                key = (src, dst)
                with self.syn_flood_lock:
                    if key not in self.syn_flood:
                        self.syn_flood[key] = RateTracker(window_sec=1.0)
                    rt = self.syn_flood[key]
                    rt.tick(ts)
                    if rt.rate(ts) >= self.config.syn_flood_threshold:
                        rt.clear()
                        self._emit({
                            "rule": "detect_tcp_syn_flood",
                            "severity": "HIGH",
                            "src_ip": src,
                            "dst_ip": dst,
                            "timestamp": ts,
                            "protocol": "TCP",
                            "description": f"TCP SYN flood suspected from {src} to {dst}",
                            "evidence": {
                                "rate_pps": rt.rate(ts),
                                "threshold_pps": self.config.syn_flood_threshold,
                            },
                            "tags": ["dos"],
                        })

        if src and dst:
            from .utils import is_private_ip
            if is_private_ip(src) and not is_private_ip(dst):
                key = (src, dst)
                with self.beaconing_lock:
                    if key not in self.beaconing:
                        self.beaconing[key] = (ts, OnlineStats())
                    else:
                        prev_ts, stats = self.beaconing[key]
                        interval = ts - prev_ts
                        if interval > 0:
                            stats.add(interval)
                            self.beaconing[key] = (ts, stats)
                            if stats.count >= self.config.beacon_min_samples:
                                cov = stats.cov
                                if cov < self.config.beacon_cov_threshold:
                                    self._emit({
                                        "rule": "detect_beaconing",
                                        "severity": "HIGH",
                                        "src_ip": src,
                                        "dst_ip": dst,
                                        "timestamp": ts,
                                        "description": (
                                            "Regular outbound connection intervals "
                                            "suggest beaconing"
                                        ),
                                        "evidence": {
                                            "mean_interval": stats.mean,
                                            "stdev": stats.stdev,
                                            "cov": cov,
                                            "count": stats.count,
                                        },
                                        "tags": ["c2"],
                                    })

    def _emit(self, alert: dict[str, Any]) -> None:
        rule = alert.get("rule", "")
        src = alert.get("src_ip", "")
        dst = alert.get("dst_ip", "")
        cooldown_key = (rule, src, dst)
        if self._alert_cooldown.get(cooldown_key) is not None:
            return
        self._alert_cooldown.set(cooldown_key, True)
        self._alerts_emitted += 1
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                self._consumer_errors += 1

    def _periodic_prune(self) -> None:
        now = time.time()
        with self.syn_scan_lock:
            stale = [k for k, v in self.syn_scan.items() if v.unique_count(now) == 0]
            for k in stale:
                del self.syn_scan[k]
        with self.udp_scan_lock:
            stale = [k for k, v in self.udp_scan.items() if v.unique_count(now) == 0]
            for k in stale:
                del self.udp_scan[k]
        with self.icmp_sweep_lock:
            stale = [k for k, v in self.icmp_sweep.items() if v.unique_count(now) == 0]
            for k in stale:
                del self.icmp_sweep[k]
        with self.dns_exfil_lock:
            stale = [k for k, v in self.dns_exfil.items() if v.unique_count(now) == 0]
            for k in stale:
                del self.dns_exfil[k]
        with self.icmp_flood_lock:
            stale = [k for k, v in self.icmp_flood.items() if v.rate(now) == 0]
            for k in stale:
                del self.icmp_flood[k]
        with self.syn_flood_lock:
            stale = [k for k, v in self.syn_flood.items() if v.rate(now) == 0]
            for k in stale:
                del self.syn_flood[k]
        self.arp_spoofing.prune(now)
        self._alert_cooldown.prune(now)

    @staticmethod
    def _import_scapy() -> Any:
        try:
            import scapy.all as scapy
            return scapy
        except ImportError:
            raise ImportError(
                "scapy is required for live capture. Install with: pip install scapy"
            )
