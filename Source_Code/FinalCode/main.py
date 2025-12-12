import os
import socket
import subprocess
import re
import time
import traceback
from typing import List

import pywifi
from pywifi import const
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from rich.box import ROUNDED

# Keep encryption functions untouched; triple_enc provides the core flows.
from triple_enc import multilayer_encrypt_flow, multilayer_decrypt_flow

console = Console()


# -------------------------
# Helper: Windows SSID fetch
# -------------------------
def get_connected_ssid_windows():
    """Return SSID via `netsh wlan show interfaces` on Windows, or None on failure."""
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        match = re.search(r"SSID\s*:\s*(.+)", output)
        if match:
            return match.group(1).strip()
        return None
    except Exception:
        return None


# -------------------------
# UI panels
# -------------------------
def header_panel() -> Panel:
    banner = Text(
        "\n".join(
            [
                "███╗   ███╗██╗   ██╗██╗  ████████╗██╗     ██╗      █████╗ ██╗   ██╗███████╗██████╗     ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ ██████╗ ███╗   ██╗",
                "████╗ ████║██║   ██║██║  ╚══██╔══╝██║     ██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║",
                "██╔████╔██║██║   ██║██║     ██║   ██║     ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║   ██║██╔██╗ ██║",
                "██║╚██╔╝██║██║   ██║██║     ██║   ██║     ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██     ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║   ██║██║╚██╗██║",
                "██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║     ███████╗██║  ██║   ██║   ███████╗██║  ██║    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ██║╚██████╔╝██║ ╚████║",
                "╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝",
            ]
        ),
        style="bold cyan",
        justify="center",
    )
    subtitle = Text("Final Individual Project Cryptography", style="bold red", justify="center")
    content = Align.center(Text.assemble(banner, "\n", subtitle))
    return Panel(content, box=ROUNDED, border_style="bright_blue", padding=(0, 1))


def system_panel() -> Panel:
    """Show system / WiFi status using pywifi (best-effort)."""
    # Host / IP
    hostname = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ipv4_address = s.getsockname()[0]
    except Exception:
        ipv4_address = "Unknown"
    finally:
        s.close()

    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()

    if not interfaces:
        iface_name = "No WiFi Interface"
        ssid = "N/A"
        band = "N/A"
        signal = "N/A"
        freq = "N/A"
        channel = "N/A"
    else:
        iface = interfaces[0]
        iface_name = iface.name()
        ssid = get_connected_ssid_windows()
        band = "Unknown"
        signal = "-"
        freq = "-"
        channel = "-"
        # scan and match details
        iface.scan()
        time.sleep(1.5)
        networks = iface.scan_results()
        for net in networks:
            if net.ssid == ssid:
                signal = net.signal
                freq = net.freq
                if net.freq < 3000:
                    channel = int((net.freq - 2407) / 5)
                    band = "2.4GHz"
                else:
                    channel = int((net.freq - 5000) / 5)
                    band = "5GHz"
                break

    tab = Table.grid(padding=(0, 1))
    tab.add_column("k", style="yellow", ratio=1)
    tab.add_column("v", style="cyan", ratio=2)
    tab.add_row("Interface :", iface_name)
    tab.add_row("Environment :", "Windows")
    tab.add_row("IPv4 :", ipv4_address)
    tab.add_row("Hostname :", hostname)
    tab.add_row("Connected SSID :", ssid or "Not Connected")
    tab.add_row("Signal :", str(signal))
    tab.add_row("Frequency :", str(freq))
    tab.add_row("Band :", f"{band} (Channel {channel})")

    return Panel(tab, title="[bold]SYSTEM STATUS[/bold]", border_style="bright_blue", box=ROUNDED, padding=(1, 2))


def menu_panel() -> Panel:
    """Main menu with actions."""
    menu = Table.grid(padding=(0, 1))
    menu.add_column("opt", justify="center", style="bold cyan", width=6)
    menu.add_column("desc", style="white")
    menu.add_row("[1]", "Multilayer Encryption (ChaCha20 → AES → Blowfish → RC4)")
    menu.add_row("[2]", "Multilayer Decryption (RC4 → Blowfish → AES → ChaCha20)")
    menu.add_row("[0]", "[bold red]Exit & Cleanup[/bold red]")
    menu.add_row("", "")
    menu.add_row("[L]", "View recent logs")
    menu.add_row("[C]", "Clear logs")
    return Panel(menu, title="[bold yellow]ENCRYPTION MAIN MENU[/bold yellow]", border_style="bright_blue", box=ROUNDED, padding=(1, 2))


def logs_panel(logs: List[str]) -> Panel:
    """Show recent logs (up to last 12 lines visible)."""
    if not logs:
        body = Text("No logs yet.", style="dim")
    else:
        body = Text("\n".join(logs[-12:]), style="green")
    return Panel(body, title="[bold]LOGS[/bold]", border_style="bright_blue", box=ROUNDED, padding=(1, 2))


# -------------------------
# Layout & logging helpers
# -------------------------
def make_layout(logs: List[str]) -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=9),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=10),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=3),
    )
    layout["header"].update(header_panel())
    layout["left"].update(system_panel())
    layout["right"].update(menu_panel())
    layout["footer"].update(logs_panel(logs))
    return layout


def log_append(logs: List[str], msg: str):
    """Append a timestamped message, keep last 200 entries."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{ts}] {msg}")
    if len(logs) > 200:
        del logs[0 : len(logs) - 200]


# -------------------------
# Interactive main loop
# -------------------------
def main():
    logs: List[str] = []
    while True:
        layout = make_layout(logs)
        console.print(layout)

        try:
            choice = Prompt.ask("[bold green]Choose action[/bold green]", choices=["1", "2", "0", "L", "C"], default="1")
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted by user. Exiting.[/bold red]")
            break

        if choice == "1":
            log_append(logs, "User selected: Multilayer Encryption")
            console.print("\n[bold cyan]Launching multilayer_encrypt_flow()...[/bold cyan]\n")
            try:
                multilayer_encrypt_flow()
                log_append(logs, "Encryption flow completed successfully.")
            except Exception as e:
                tb = traceback.format_exc()
                console.print(f"[bold red]Encryption flow raised an exception:[/bold red]\n{tb}")
                log_append(logs, f"Encryption flow error: {e}")

        elif choice == "2":
            log_append(logs, "User selected: Multilayer Decryption")
            console.print("\n[bold cyan]Launching multilayer_decrypt_flow()...[/bold cyan]\n")
            try:
                multilayer_decrypt_flow()
                log_append(logs, "Decryption flow completed successfully.")
            except Exception as e:
                tb = traceback.format_exc()
                console.print(f"[bold red]Decryption flow raised an exception:[/bold red]\n{tb}")
                log_append(logs, f"Decryption flow error: {e}")

        elif choice == "L":
            console.print(Panel(Text("\n".join(logs[-200:]) if logs else "No logs yet.", style="green"), title="Recent Logs", border_style="bright_blue"))
          

        elif choice == "C":
            logs.clear()
            log_append(logs, "Logs cleared by user.")
            console.print("[bold yellow]Logs cleared.[/bold yellow]")
            time.sleep(0.8)

        elif choice == "0":
            log_append(logs, "User selected Exit.")
            console.print("\n[bold cyan]Exiting... Goodbye.[/bold cyan]")
            break

        else:
            log_append(logs, f"Invalid selection: {choice}")
            console.print("[bold red]Invalid choice.[/bold red]")
            time.sleep(0.6)

        console.print("\nPress Enter to continue...")
        console.input()


if __name__ == "__main__":
    main()
