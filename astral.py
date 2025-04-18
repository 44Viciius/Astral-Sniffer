import argparse
import threading
import time
import json
import csv
from collections import defaultdict
from scapy.all import sniff, wrpcap, DNS, IP, TCP, UDP, Ether, IPv6
from scapy.layers.http import HTTPRequest
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

def print_logo():
    logo = [
        f"{Fore.YELLOW}  /$$$$$$              /$$                        /$$          /$$$$$$            /$$  /$$$$$$   /$$$$$$                   ",
        f"{Fore.CYAN} /$$__  $$            | $$                       | $$         /$$__  $$          |__/ /$$__  $$ /$$__  $$                  ",
        f"{Fore.GREEN}| $$  \\ $$  /$$$$$$$ /$$$$$$    /$$$$$$  /$$$$$$ | $$        | $$  \\__/ /$$$$$$$  /$$| $$  \\__/| $$  \\__//$$$$$$   /$$$$$$ ",
        f"{Fore.MAGENTA}| $$$$$$$$ /$$_____/|_  $$_/   /$$__  $$|____  $$| $$ /$$$$$$|  $$$$$$ | $$__  $$| $$| $$$$    | $$$$   /$$__  $$ /$$__  $$",
        f"{Fore.RED}| $$__  $$|  $$$$$$   | $$    | $$  \\__/ /$$$$$$$| $$|______/ \\____  $$| $$  \\ $$| $$| $$_/    | $$_/  | $$$$$$$$| $$  \\__/",
        f"{Fore.BLUE}| $$  | $$ \\____  $$  | $$ /$$| $$      /$$__  $$| $$         /$$  \\ $$| $$  | $$| $$| $$      | $$    | $$_____/| $$      ",
        f"{Fore.CYAN}| $$  | $$ /$$$$$$$/  |  $$$$/| $$     |  $$$$$$$| $$        |  $$$$$$/| $$  | $$| $$| $$      | $$    |  $$$$$$$| $$      ",
        f"{Fore.GREEN}|__/  |__/|_______/    \\___/  |__/      \\_______/|__/         \\______/ |__/  |__/|__/|__/      |__/     \\_______/|__/      ",
        f"{Style.RESET_ALL}"
    ]
    for line in logo:
        print(line)
    print(f"{Fore.MAGENTA}By44Viciius<3\n")

stats = defaultdict(int)
capturing = True

def capture_packets(interface, count, filter_type, save_interval, auto_save_path):
    def packet_filter(packet):
        if filter_type == "http" and packet.haslayer(HTTPRequest):
            return True
        elif filter_type == "dns" and packet.haslayer(DNS):
            return True
        elif filter_type == "ipv6" and packet.haslayer(IPv6):
            return True
        elif filter_type == "ftp" and packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            return True
        elif filter_type == "tls" and packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            return True
        return True

    print(f"Iniciando captura en la interfaz {interface} con filtro: {filter_type or 'ninguno'}...")

    captured_packets = []

    def save_captures():
        while capturing:
            if save_interval > 0:
                time.sleep(save_interval)
                if captured_packets:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"{auto_save_path}/capture_{timestamp}.pcap"
                    wrpcap(filename, captured_packets)
                    print(f"Guardado automático: {filename}")

    if auto_save_path:
        threading.Thread(target=save_captures, daemon=True).start()

    def process_packet(packet):
        if packet_filter(packet):
            captured_packets.append(packet)
            update_stats(packet)

    sniff(iface=interface, count=count, prn=process_packet)
    print("Captura finalizada.")
    return captured_packets

def update_stats(packet):
    if packet.haslayer(HTTPRequest):
        stats["http"] += 1
    elif packet.haslayer(DNS):
        stats["dns"] += 1
    elif packet.haslayer(IPv6):
        stats["ipv6"] += 1
    elif packet.haslayer(TCP) and packet[TCP].dport == 443:
        stats["tls"] += 1
    elif packet.haslayer(TCP) and packet[TCP].dport == 21:
        stats["ftp"] += 1
    else:
        stats["otros"] += 1

def export_stats_to_csv(filename):
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Protocolo", "Cantidad"])
        for key, value in stats.items():
            writer.writerow([key, value])
    print(f"Estadísticas exportadas a {filename}")

def export_stats_to_json(filename):
    with open(filename, "w") as jsonfile:
        json.dump(stats, jsonfile, indent=4)
    print(f"Estadísticas exportadas a {filename}")

def main():
    print_logo()

    parser = argparse.ArgumentParser(
        description="Astral-Sniffer: Una herramienta avanzada para capturar y analizar tráfico de red.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--interface", required=True, help="Interfaz de red (ej. 'eth0', 'en0', etc.).")
    parser.add_argument("--count", type=int, default=0, help="Número de paquetes a capturar (0 = infinito).")
    parser.add_argument("--filter", choices=["http", "dns", "ftp", "tls", "ipv6"], help="Filtrar tráfico por protocolo.")
    parser.add_argument("--save-interval", type=int, default=0, help="Intervalo de guardado automático en segundos.")
    parser.add_argument("--auto-save-path", type=str, help="Ruta donde se guardarán automáticamente las capturas (formato PCAP).")
    parser.add_argument("--export-csv", type=str, help="Exporta estadísticas a un archivo CSV.")
    parser.add_argument("--export-json", type=str, help="Exporta estadísticas a un archivo JSON.")

    args = parser.parse_args()

    packets = capture_packets(
        interface=args.interface,
        count=args.count,
        filter_type=args.filter,
        save_interval=args.save_interval,
        auto_save_path=args.auto_save_path
    )

    if args.export_csv:
        export_stats_to_csv(args.export_csv)

    if args.export_json:
        export_stats_to_json(args.export_json)

if __name__ == "__main__":
    main()
