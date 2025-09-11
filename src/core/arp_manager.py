# src/core/arp_manager.py
"""
ARP Manager

Provides a single, thread-safe manager that controls ARP spoofing
in the application. It wraps the low-level ARPSpoofThread and exposes
a higher-level API with PyQt signals for the GUI(s).

Main responsibilities:
 - ensure only one active spoof operation at a time
 - start / stop / verify spoofing with retries
 - provide emergency restoration helper
 - emit consistent signals so multiple GUI tabs can subscribe to state

All public methods are non-blocking or return quickly; long-running
verification/restore waits are performed in background threads.
"""

from typing import Optional, Dict, Any
import threading
import time

from PyQt5.QtCore import QObject, pyqtSignal, QThread

# import the existing ARP spoof implementation
try:
    from core.arp_spoof import ARPSpoofThread, check_arp_spoof_success, sniff_arp_poisoning
except Exception:
    ARPSpoofThread = None
    check_arp_spoof_success = None
    sniff_arp_poisoning = None

# optional scapy helpers for emergency restore
try:
    from scapy.all import sendp, Ether, ARP, getmacbyip, conf as scapy_conf
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False


class _VerifyThread(QThread):
    """
    Background thread to verify that ARP spoofing is in effect.
    Emits verified(bool, message).
    """
    verified = pyqtSignal(bool, str)

    def __init__(self, victim_ip: str, gateway_ip: str, attempts: int = 3, interval: int = 2, parent=None):
        super().__init__(parent)
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attempts = attempts
        self.interval = interval
        self._stop_requested = False

    def run(self):
        if check_arp_spoof_success is None:
            self.verified.emit(False, "check_arp_spoof_success unavailable")
            return

        for attempt in range(1, self.attempts + 1):
            if self._stop_requested:
                self.verified.emit(False, "verification cancelled")
                return
            try:
                ok = check_arp_spoof_success(self.victim_ip, self.gateway_ip)
            except Exception:
                ok = False
            if ok:
                self.verified.emit(True, f"verified on attempt {attempt}")
                return
            # wait before retrying
            time.sleep(self.interval)
        self.verified.emit(False, "not verified after attempts")

    def stop(self):
        self._stop_requested = True


class ARPManager(QObject):
    """
    Central manager for ARP spoofing control.

    Signals:
      - log_event(str): debugging/logging info for UIs
      - spoof_started(target, gateway)
      - spoof_verified(target, gateway, message)
      - spoof_failed(target, gateway, reason)
      - spoof_stopped(target, gateway, restored_bool)
    """

    log_event = pyqtSignal(str)
    spoof_started = pyqtSignal(str, str)
    spoof_verified = pyqtSignal(str, str, str)
    spoof_failed = pyqtSignal(str, str, str)
    spoof_stopped = pyqtSignal(str, str, bool)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._lock = threading.Lock()
        self._thread: Optional[ARPSpoofThread] = None
        self._verify_thread: Optional[_VerifyThread] = None
        self._state: Dict[str, Any] = {
            "running": False,
            "target": None,
            "gateway": None,
            "iface": None,
            "verified": False,
            "started_at": None
        }

    # -------------------------
    # Internal helpers
    # -------------------------
    def _emit_log(self, message: str) -> None:
        try:
            self.log_event.emit(message)
        except Exception:
            # safe fallback: ignore emit errors
            pass

    # -------------------------
    # Public API
    # -------------------------
    def start_spoof(
        self,
        target_ip: str,
        gateway_ip: str,
        iface: Optional[str] = None,
        interval: int = 2,
        verify_attempts: int = 3,
        verify_interval: int = 2
    ) -> bool:
        """
        Start ARP spoofing between target_ip and gateway_ip.

        Returns True if a spoof thread was started (or already running for same pair).
        Returns False if starting was refused (another spoof is running for a different pair).
        """
        if ARPSpoofThread is None:
            self._emit_log("[ARPManager] ARPSpoofThread backend unavailable")
            return False
        with self._lock:
            if self._state["running"]:
                # if same target/gateway, treat as ok (idempotent)
                if self._state["target"] == target_ip and self._state["gateway"] == gateway_ip:
                    self._emit_log(f"[ARPManager] Spoof already running for {target_ip} <-> {gateway_ip}")
                    return True
                else:
                    self._emit_log("[ARPManager] Another spoof is already running; refuse to start a second one")
                    return False

            # create and start ARPSpoofThread
            try:
                # optionally set scapy conf.iface if provided
                if iface:
                    try:
                        from scapy.all import conf as scapy_conf_mod
                        scapy_conf_mod.iface = iface
                    except Exception:
                        pass

                self._thread = ARPSpoofThread(target_ip, gateway_ip, interval=interval)
                # connect finish signal for logging and to update state
                self._thread.finished.connect(lambda: self._on_thread_finished(target_ip, gateway_ip))
                self._thread.start()

                # update state
                self._state.update({
                    "running": True,
                    "target": target_ip,
                    "gateway": gateway_ip,
                    "iface": iface,
                    "verified": False,
                    "started_at": time.time()
                })
                self._emit_log(f"[ARPManager] Spoof started for {target_ip} <-> {gateway_ip}")
                self.spoof_started.emit(target_ip, gateway_ip)

                # start verification thread
                if check_arp_spoof_success is not None:
                    self._verify_thread = _VerifyThread(target_ip, gateway_ip, attempts=verify_attempts, interval=verify_interval)
                    self._verify_thread.verified.connect(lambda ok, msg: self._on_verify_result(ok, msg, target_ip, gateway_ip))
                    self._verify_thread.start()
                else:
                    # no verification available: emit failed info
                    self._emit_log("[ARPManager] Verification function unavailable; skipping verification")
                    self.spoof_failed.emit(target_ip, gateway_ip, "verification unavailable")

                return True
            except Exception as e:
                self._emit_log(f"[ARPManager] Failed to start spoof thread: {e}")
                self._state.update({"running": False, "target": None, "gateway": None, "iface": None, "verified": False})
                return False

    def _on_verify_result(self, ok: bool, message: str, target: str, gateway: str) -> None:
        """
        Internal handler for verify thread results.
        """
        with self._lock:
            if not self._state["running"]:
                # spoof stopped while verification was ongoing
                self._emit_log("[ARPManager] Verification result arrived but spoof not running")
                return

            if self._state["target"] != target or self._state["gateway"] != gateway:
                # state changed in meantime
                self._emit_log("[ARPManager] Verification result does not match current spoof target/gateway")
                return

            if ok:
                self._state["verified"] = True
                self._emit_log(f"[ARPManager] Spoof verified: {message}")
                self.spoof_verified.emit(target, gateway, message)
            else:
                self._state["verified"] = False
                self._emit_log(f"[ARPManager] Spoof verification failed: {message}")
                self.spoof_failed.emit(target, gateway, message)

            # clear verify thread reference
            self._verify_thread = None

    def _on_thread_finished(self, target: str, gateway: str) -> None:
        """
        ARPSpoofThread finished: update state and emit spoof_stopped.
        Note: the ARPSpoofThread implementation is expected to attempt restoration
        as part of its shutdown; here we perform a best-effort verification to see
        if the restoration succeeded.
        """
        restored = True
        try:
            # after thread finished, check whether victim no longer maps gateway to attacker
            if check_arp_spoof_success is not None:
                # check_arp_spoof_success returns True if victim associates gateway with attacker -> BAD
                still_poisoned = check_arp_spoof_success(self._state["target"], self._state["gateway"])
                restored = not bool(still_poisoned)
        except Exception:
            # if verification fails, be conservative and mark not restored
            restored = False

        with self._lock:
            self._emit_log(f"[ARPManager] Spoof thread finished for {target} <-> {gateway}, restored={restored}")
            # reset state
            self._state.update({"running": False, "target": None, "gateway": None, "iface": None, "verified": False, "started_at": None})
            self._thread = None
        try:
            self.spoof_stopped.emit(target, gateway, restored)
        except Exception:
            pass

    def stop_spoof(self, wait_for_restore: bool = True, timeout_ms: int = 5000) -> bool:
        """
        Request stopping the currently running spoof.

        If wait_for_restore is True, wait up to timeout_ms milliseconds for the worker
        to finish and attempt restoration. Returns True if restore appears successful (best-effort),
        False otherwise (including case where no spoof was running).
        """
        with self._lock:
            if not self._state["running"] or self._thread is None:
                self._emit_log("[ARPManager] No spoof running to stop")
                return True  # nothing to stop -> treat as success

            target = self._state["target"]
            gateway = self._state["gateway"]
            thr = self._thread

            # request stop
            try:
                thr.stop()
            except Exception as e:
                self._emit_log(f"[ARPManager] Error requesting thread stop: {e}")

        # optionally wait for thread to finish
        restored = False
        if wait_for_restore:
            try:
                # convert ms to seconds for wait
                waited = thr.wait(timeout_ms)
                # After thread finished, perform verification: ensure victim no longer maps gateway to attacker
                if check_arp_spoof_success is not None:
                    try:
                        still_poisoned = check_arp_spoof_success(target, gateway)
                        restored = not bool(still_poisoned)
                    except Exception:
                        restored = False
                else:
                    # verification not available; assume best-effort restore attempted
                    restored = True
            except Exception:
                restored = False
        else:
            # do not wait; we cannot guarantee restoration
            restored = False

        # clear internal state under lock
        with self._lock:
            self._thread = None
            self._state.update({"running": False, "target": None, "gateway": None, "iface": None, "verified": False, "started_at": None})

        try:
            self.spoof_stopped.emit(target, gateway, restored)
        except Exception:
            pass

        self._emit_log(f"[ARPManager] stop_spoof requested for {target} <-> {gateway}, restored={restored}")
        return restored

    def emergency_restore(self, target_ip: str, gateway_ip: str, iface: Optional[str] = None) -> bool:
        """
        Best-effort emergency restoration. Uses scapy if available to send
        gratuitous ARP replies to restore the mapping.
        Returns True on success (MACs resolved and packets sent), False otherwise.
        """
        if not _HAS_SCAPY:
            self._emit_log("[ARPManager] scapy not available for emergency_restore")
            return False

        try:
            if iface:
                scapy_conf.iface = iface
            victim_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(gateway_ip)
            if not victim_mac or not gateway_mac:
                self._emit_log("[ARPManager] emergency_restore: couldn't resolve MAC addresses")
                return False

            # send several gratuitous ARP replies
            for _ in range(5):
                sendp(Ether(dst=victim_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac), iface=iface, verbose=False)
                sendp(Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwsrc=victim_mac), iface=iface, verbose=False)
                time.sleep(0.2)

            self._emit_log("[ARPManager] emergency restore packets sent")
            return True
        except Exception as e:
            self._emit_log(f"[ARPManager] emergency_restore exception: {e}")
            return False

    def status(self) -> Dict[str, Any]:
        """
        Return a snapshot of manager state.
        """
        with self._lock:
            return dict(self._state)


# -----------------------------------------------------------------------------
# Module-level singleton for convenience. Importers can use `arp_manager`.
# -----------------------------------------------------------------------------
_arp_manager = ARPManager()
def get_arp_manager() -> ARPManager:
    return _arp_manager

# expose a commonly-named variable
arp_manager = _arp_manager