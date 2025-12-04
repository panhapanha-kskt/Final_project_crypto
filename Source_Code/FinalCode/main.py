# main_rich_ui.py
import os
import time
import traceback
from typing import List

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from rich.box import ROUNDED

#Real Time Detect WiFi Info
import pywifi
from pywifi import const
import time
import socket
import subprocess
import re

def get_connected_ssid_windows():
    """Uses netsh to get currently connected SSID"""
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            text=True, encoding="utf-8", errors="ignore"
        )
        match = re.search(r"SSID\s*:\s*(.+)", output)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None
    


# --- Keep your encryption functions untouched ---
from triple_enc import multilayer_encrypt_flow, multilayer_decrypt_flow

console = Console()

# ---------------------
# UI pieces rendering
# ---------------------
def header_panel() -> Panel:
    banner = Text(
        "\n".join([
            # MULTI LAYER
            "███╗   ███╗██╗   ██╗██╗  ████████╗██╗     ██╗      █████╗ ██╗   ██╗███████╗██████╗     ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ ██████╗ ███╗   ██╗",
            "████╗ ████║██║   ██║██║  ╚══██╔══╝██║     ██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║",
            "██╔████╔██║██║   ██║██║     ██║   ██║     ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║   ██║██╔██╗ ██║",
            "██║╚██╔╝██║██║   ██║██║     ██║   ██║     ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██     ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║   ██║██║╚██╗██║",
            "██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║     ███████╗██║  ██║   ██║   ███████╗██║  ██║    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ██║╚██████╔╝██║ ╚████║",
            "╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝",
        ]),
        style="bold cyan",
        justify="center",
    )
    subtitle = Text("Final Individual Project Cryptography", style="bold red", justify="center")
    content = Align.center(Text.assemble(banner, "\n", subtitle))
    return Panel(content, box=ROUNDED, border_style="bright_blue", padding=(0, 1))

#Real time wifi info panel
def system_panel() -> Panel:
    # Identify PC
    hostname = socket.gethostname()

    # Get IPv4 address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ipv4_address = s.getsockname()[0]
    except:
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
        # Windows SSID detection
        ssid = get_connected_ssid_windows()
        # Default values
        band = "Unknown"
        signal = "-"
        freq = "-"
        channel = "-"
        # Scan for details
        iface.scan()
        time.sleep(1.5)
        networks = iface.scan_results()
        # Match scanned SSID
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
    # Build panel table
    tab = Table.grid(padding=(0,1))
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

    return Panel(
        tab,
        title="[bold]SYSTEM STATUS[/bold]",
        border_style="bright_blue",
        box=ROUNDED,
        padding=(1,2)
    )

def menu_panel() -> Panel:
    menu = Table.grid(padding=(0,1))
    menu.add_column("opt", justify="center", style="bold cyan", width=6)
    menu.add_column("desc", style="white")
    menu.add_row("[1]", "Multilayer Encryption (ChaCha20 → AES → Blowfish → RC4)")
    menu.add_row("[2]", "Multilayer Decryption (RC4 → Blowfish → AES → ChaCha20)")
    menu.add_row("[0]", "[bold red]Exit & Cleanup[/bold red]")
    menu.add_row("", "")
    menu.add_row("[L]", "View recent logs")
    menu.add_row("[C]", "Clear logs")
    return Panel(menu, title="[bold yellow]ENCRYPTION MAIN MENU[/bold yellow]", border_style="bright_blue", box=ROUNDED, padding=(1,2))

def logs_panel(logs: List[str]) -> Panel:
    if not logs:
        body = Text("No logs yet.", style="dim")
    else:
        body = Text("\n".join(logs[-12:]), style="green")
    return Panel(body, title="[bold]LOGS[/bold]", border_style="bright_blue", box=ROUNDED, padding=(1,2))

# ---------------------
# Render full layout
# ---------------------
def make_layout(logs: List[str]) -> Layout:
    layout = Layout(name="root")

    # top banner (20% height)
    layout.split_column(
        Layout(name="header", size=9),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=10),
    )

    # split body into left and right
    layout["body"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=3),
    )

    # put content
    layout["header"].update(header_panel())
    layout["left"].update(system_panel())
    layout["right"].update(menu_panel())
    layout["footer"].update(logs_panel(logs))

    return layout

# ---------------------
# Logging helpers
# ---------------------
def log_append(logs: List[str], msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{ts}] {msg}")
    # keep last 200 entries max
    if len(logs) > 200:
        del logs[0: len(logs)-200]

# ---------------------
# Main interactive loop
# ---------------------
def main():
    logs: List[str] = []
    while True:
        layout = make_layout(logs)
        console.print(layout)

        # use Prompt to read single-character commands nicely
        try:
            choice = Prompt.ask("[bold green]Choose action[/bold green]", choices=["1","2","0","L","C"], default="1")
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted by user. Exiting.[/bold red]")
            break

        # keep a copy of screen before running blocking encrypt/decrypt flows
        if choice == "1":
            log_append(logs, "User selected: Multilayer Encryption")
            console.print("\n[bold cyan]Launching multilayer_encrypt_flow()...[/bold cyan]\n")
            try:
                # the encryption function uses input()/print() internally; keep UI intact
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
            # show logs in a simple pager-like view
            console.print(Panel(Text("\n".join(logs[-200:]) if logs else "No logs yet.", style="green"), title="Recent Logs", border_style="bright_blue"))
            console.input("\nPress Enter to return to menu...")
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

        # small pause to allow user to read results (actual encryption prints may have paused already)
        console.print("\nPress Enter to continue...")
        console.input()
    # end while

if __name__ == "__main__":
    main()
