#!/usr/bin/env python3
import subprocess
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, Dot11Deauth
except ImportError:
    subprocess.run(["pip3", "install", "scapy"], check=True)
    from scapy.all import sniff, Dot11Deauth

from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel

# إعدادات
INTERFACE = "wlan0"
MONITOR_INTERFACE = INTERFACE + "mon"
LOG_FILE = "deauth_detector.log"
THRESHOLD = 15
RESET_INTERVAL = 10

console = Console()

class Detector:
    def __init__(self):
        self.counts = defaultdict(int)
        self.alerted = set()
        self.running = False
        self.timer = None
        self.thread = None
        self.setup_log()

    def setup_log(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
        )

    def enable_monitor_mode(self):
        try:
            subprocess.run(["sudo", "airmon-ng", "start", INTERFACE], check=True)
            return True
        except Exception as err:
            logging.error(f"Failed to enable monitor mode: {err}")
            return False

    def disable_monitor_mode(self):
        try:
            subprocess.run(["sudo", "airmon-ng", "stop", MONITOR_INTERFACE], check=True)
        except Exception as err:
            logging.error(f"Failed to disable monitor mode: {err}")

    def reset_counts(self):
        self.counts.clear()
        self.alerted.clear()
        self.timer = threading.Timer(RESET_INTERVAL, self.reset_counts)
        self.timer.start()

    def process_packet(self, pkt):
        if pkt.haslayer(Dot11Deauth):
            attacker = pkt.addr2 or "Unknown"
            self.counts[attacker] += 1
            if self.counts[attacker] > THRESHOLD and attacker not in self.alerted:
                logging.warning(f"Possible attack from {attacker} ({self.counts[attacker]} frames)")
                self.alerted.add(attacker)

    def build_table(self):
        tbl = Table(title="Deauth Monitor")
        tbl.add_column("MAC", justify="center")
        tbl.add_column("Frames", justify="center")
        tbl.add_column("Status", justify="center")
        for mac, val in self.counts.items():
            status = "ATTACK" if val > THRESHOLD else "Watching"
            tbl.add_row(mac, str(val), status)
        return tbl

    def capture(self):
        try:
            logging.info("Started capturing packets...")
            with Live(self.build_table(), refresh_per_second=1, screen=True) as live:
                while self.running:
                    sniff(iface=MONITOR_INTERFACE, prn=self.process_packet, timeout=1, store=False, monitor=True)
                    live.update(self.build_table())
        except Exception as err:
            logging.error(f"Capture error: {err}")
            self.stop()

    def start(self):
        if not self.enable_monitor_mode():
            return False
        self.running = True
        self.reset_counts()
        self.thread = threading.Thread(target=self.capture)
        self.thread.start()
        return True

    def stop(self):
        self.running = False
        if self.timer:
            self.timer.cancel()
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.disable_monitor_mode()
        logging.info("Stopped")

def main():
    console.print(Panel("[bold]WiFi Deauth Detector[/bold]", title="Linux Terminal Dashboard", expand=False))
    d = Detector()
    try:
        if d.start():
            console.print("[green]Running. Press Ctrl+C to exit.[/green]")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopped by user.")
    except Exception as err:
        logging.error(f"Error: {err}")
    finally:
        d.stop()
        print("Exiting.")

if __name__ == "__main__":
    main()
