# src/core/capture.py
"""
Traffic capture backend.

Provides TrafficCapture QThread which performs live packet capture using pyshark (preferred)
and falls back to scapy.sniff() when tshark/pyshark is not available.

Signals:
 - packet_captured: emits a lightweight dict summary for UI tables
 - packet_detail: emits a verbose string representation for inspection panel
 - started: emitted when capture begins
 - stopped: emitted when capture ends
 - error: emits error messages

API:
 - start_capture(interface, bpf_filter="", display_filter=None, save_file=None, max_packets=None)
 - stop_capture()
 - is_running()
"""

from typing import Optional, Dict, Any
import subprocess
import logging
import shutil
import time

from PyQt5.QtCore import QThread, pyqtSignal

# try to import pyshark lazily
try:
    import pyshark
    _HAS_PYSHARK = True
except Exception:
    pyshark = None
    _HAS_PYSHARK = False

# scapy fallback
try:
    from scapy.all import sniff, Ether, IP, IPv6, ARP
    _HAS_SCAPY = True
except Exception:
    sniff = None
    _HAS_SCAPY = False

from .capture_adapter import check_tshark_installed

logger = logging.getLogger(__name__)


class TrafficCapture(QThread):
    packet_captured = pyqtSignal(dict)   # lightweight summary
    packet_detail = pyqtSignal(str)      # verbose details (pretty print / xml / str)
    started = pyqtSignal()
    stopped = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._iface: Optional[str] = None
        self._bpf: str = ""
        self._display_filter: Optional[str] = None
        self._save_file: Optional[str] = None
        self._max_packets: Optional[int] = None
        self._running = False
        self._tshark_proc: Optional[subprocess.Popen] = None
        self._use_pyshark = False

    # -------------------------
    # Public API
    # -------------------------
    def start_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        display_filter: Optional[str] = None,
        save_file: Optional[str] = None,
        max_packets: Optional[int] = None,
    ) -> None:
        """
        Configure capture parameters and start thread.
        This method is non-blocking: it starts the QThread which runs run().
        """
        if self._running:
            self.error.emit("Capture already running")
            return

        self._iface = interface
        self._bpf = bpf_filter or ""
        self._display_filter = display_filter
        self._save_file = save_file
        self._max_packets = max_packets
        # decide capture backend: prefer pyshark if tshark installed and pyshark imported
        self._use_pyshark = _HAS_PYSHARK and check_tshark_installed()
        self._running = True
        self.start()  # QThread.start -> run()

    def stop_capture(self) -> None:
        """
        Request capture stop. This attempts to gracefully stop pyshark capture
        or scapy sniff. If a tshark subprocess was started to write PCAP, terminate it.
        """
        self._running = False
        # If we started a tshark subprocess to write file, terminate it
        if self._tshark_proc:
            try:
                self._tshark_proc.terminate()
            except Exception:
                try:
                    self._tshark_proc.kill()
                except Exception:
                    pass
            finally:
                self._tshark_proc = None

    def is_running(self) -> bool:
        return self._running

    # -------------------------
    # Internal helpers
    # -------------------------
    def _emit_summary_from_pyshark(self, pkt) -> None:
        """
        Build a lightweight summary dict from a pyshark packet.
        Keys: time, src, dst, proto, length, summary
        """
        try:
            summary: Dict[str, Any] = {}
            # sniff_time available
            try:
                summary["time"] = str(pkt.sniff_time)
            except Exception:
                summary["time"] = ""
            try:
                summary["proto"] = pkt.highest_layer
            except Exception:
                summary["proto"] = getattr(pkt, "highest_layer", "")
            # Attempt to read common endpoints (IP, IPv6, Ethernet)
            src = dst = ""
            try:
                if hasattr(pkt, "ip"):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                elif hasattr(pkt, "ipv6"):
                    src = pkt.ipv6.src
                    dst = pkt.ipv6.dst
                elif hasattr(pkt, "eth"):
                    src = pkt.eth.src
                    dst = pkt.eth.dst
            except Exception:
                pass
            summary["src"] = src or ""
            summary["dst"] = dst or ""
            try:
                summary["length"] = int(pkt.length) if hasattr(pkt, "length") else None
            except Exception:
                summary["length"] = None
            # Provide a brief info field
            try:
                summary["info"] = pkt.summary if hasattr(pkt, "summary") else str(pkt)
            except Exception:
                summary["info"] = str(pkt)
            self.packet_captured.emit(summary)
        except Exception as e:
            logger.debug(f"_emit_summary_from_pyshark error: {e}")

    def _emit_detail_from_pyshark(self, pkt) -> None:
        """
        Emit a pretty textual detail. Prefer pkt.pretty_print() if available,
        else fall back to str(pkt).
        """
        try:
            detail = ""
            try:
                detail = pkt.pretty_print()
            except Exception:
                try:
                    detail = pkt.__str__()
                except Exception:
                    detail = repr(pkt)
            self.packet_detail.emit(detail)
        except Exception as e:
            logger.debug(f"_emit_detail_from_pyshark error: {e}")

    def _emit_summary_from_scapy(self, pkt) -> None:
        """
        Build a lightweight summary dict from a scapy packet.
        """
        try:
            summary: Dict[str, Any] = {}
            summary["time"] = getattr(pkt, "time", "")
            summary["proto"] = pkt.summary().split()[0] if hasattr(pkt, "summary") else ""
            src = dst = ""
            try:
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                elif pkt.haslayer(Ether):
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst
            except Exception:
                pass
            summary["src"] = src or ""
            summary["dst"] = dst or ""
            summary["length"] = len(pkt) if hasattr(pkt, "__len__") else None
            try:
                summary["info"] = pkt.summary()
            except Exception:
                summary["info"] = str(pkt)
            self.packet_captured.emit(summary)
        except Exception as e:
            logger.debug(f"_emit_summary_from_scapy error: {e}")

    def _emit_detail_from_scapy(self, pkt) -> None:
        try:
            detail = pkt.show(dump=True)
            self.packet_detail.emit(detail)
        except Exception as e:
            try:
                self.packet_detail.emit(str(pkt))
            except Exception:
                self.packet_detail.emit(repr(pkt))

    # -------------------------
    # Thread run method
    # -------------------------
    def run(self) -> None:
        """
        Capture loop. Chooses backend based on availability and configuration.
        """
        iface = self._iface
        bpf = self._bpf
        display = self._display_filter
        save_file = self._save_file
        max_packets = self._max_packets

        if not iface:
            self.error.emit("No interface specified for capture")
            self._running = False
            self.stopped.emit()
            return

        # Emit started
        self.started.emit()

        # If save_file is requested and tshark is available, start a tshark subprocess to write pcap
        if save_file and shutil.which("tshark"):
            try:
                tshark_cmd = ["tshark", "-i", iface, "-w", save_file]
                if bpf:
                    tshark_cmd.extend(["-f", bpf])
                # Run as subprocess; we will terminate it on stop
                self._tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.debug(f"Failed to start tshark subprocess for saving pcap: {e}")
                self._tshark_proc = None

        # Prefer pyshark if available and tshark installed
        if self._use_pyshark:
            try:
                capture_kwargs = {"interface": iface}
                if bpf:
                    capture_kwargs["bpf_filter"] = bpf
                if display:
                    # pyshark LiveCapture accepts display_filter as param too
                    capture_kwargs["display_filter"] = display
                capture = pyshark.LiveCapture(**capture_kwargs)
            except Exception as e:
                # fallback to scapy if pyshark cannot create capture
                logger.debug(f"pyshark LiveCapture init failed: {e}")
                capture = None
                self._use_pyshark = False
            if capture:
                try:
                    # Iteratively yield packets
                    pkt_count = 0
                    for pkt in capture.sniff_continuously():
                        if not self._running:
                            break
                        # emit summary
                        self._emit_summary_from_pyshark(pkt)
                        # optionally emit detailed packet text asynchronously (emit every Nth or on request)
                        # here we emit a detail for every packet for simplicity (UI can ignore)
                        self._emit_detail_from_pyshark(pkt)
                        pkt_count += 1
                        if max_packets and pkt_count >= max_packets:
                            break
                    try:
                        capture.close()
                    except Exception:
                        pass
                except Exception as e:
                    logger.debug(f"pyshark sniff loop exception: {e}")
                    self.error.emit(f"pyshark capture error: {e}")
        # scapy fallback
        if not self._use_pyshark:
            if not _HAS_SCAPY:
                self.error.emit("No capture backend available (pyshark/tshark or scapy required)")
                self._running = False
                self.stopped.emit()
                return

            # scapy sniff callback
            def _scapy_callback(pkt):
                if not self._running:
                    return
                self._emit_summary_from_scapy(pkt)
                self._emit_detail_from_scapy(pkt)

            try:
                # sniff with filter and count; timeout is left out to run until stopped
                sniff_kwargs = {"iface": iface, "prn": _scapy_callback, "store": False}
                if bpf:
                    sniff_kwargs["filter"] = bpf
                if max_packets:
                    sniff_kwargs["count"] = max_packets
                # scapy.sniff is blocking. We run it — stop_capture will set _running False and may not interrupt sniff immediately.
                sniff(**sniff_kwargs)
            except Exception as e:
                logger.debug(f"scapy sniff error: {e}")
                self.error.emit(f"scapy capture error: {e}")

        # Ensure tshark subprocess terminated
        if self._tshark_proc:
            try:
                self._tshark_proc.terminate()
            except Exception:
                try:
                    self._tshark_proc.kill()
                except Exception:
                    pass
            self._tshark_proc = None

        # Finished
        self._running = False
        self.stopped.emit()
