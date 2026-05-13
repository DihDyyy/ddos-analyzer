# ============================================================================
# DDoS PCAP Analyzer - Packet Parser Module
# ============================================================================
# Sử dụng Scapy để đọc và phân tích file .pcap
# Trích xuất thông tin: IP, Protocol, Port, Flags, HTTP data
# ============================================================================

import os
import sys
from datetime import datetime
from collections import namedtuple

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

# Cấu trúc dữ liệu cho packet đã parse
ParsedPacket = namedtuple("ParsedPacket", [
    "timestamp",       # float: thời gian packet
    "src_ip",          # str: IP nguồn
    "dst_ip",          # str: IP đích
    "protocol",        # str: TCP/UDP/ICMP/OTHER
    "src_port",        # int hoặc None
    "dst_port",        # int hoặc None
    "tcp_flags",       # str hoặc None (SYN, ACK, FIN, RST, ...)
    "is_syn",          # bool: có phải SYN packet không
    "is_http",         # bool: có phải HTTP traffic không
    "http_method",     # str hoặc None (GET, POST, ...)
    "http_uri",        # str hoặc None
    "packet_size",     # int: kích thước packet (bytes)
    "raw_info",        # str: thông tin thô để debug
])


class PcapParser:
    """
    Module đọc và phân tích file .pcap sử dụng Scapy.
    Trích xuất thông tin chi tiết từ mỗi packet để phục vụ phát hiện DDoS.
    """

    # Các HTTP method phổ biến để nhận dạng HTTP traffic
    HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT"]

    def __init__(self):
        self.packets = []
        self.parsed_packets = []
        self.file_path = ""
        self.file_size = 0
        self.load_time = 0

    def load_pcap(self, filepath):
        """
        Đọc file .pcap và parse tất cả packets.

        Args:
            filepath (str): Đường dẫn tới file .pcap

        Returns:
            list[ParsedPacket]: Danh sách packets đã parse

        Raises:
            FileNotFoundError: Nếu file không tồn tại
            Exception: Nếu file không phải định dạng pcap hợp lệ
        """
        # Kiểm tra file tồn tại
        if not os.path.exists(filepath):
            console.print(f"[bold red]❌ Lỗi:[/] File không tồn tại: {filepath}")
            sys.exit(1)

        self.file_path = filepath
        self.file_size = os.path.getsize(filepath)

        console.print()
        console.print(f"[bold cyan]📂 Đang tải file:[/] {os.path.basename(filepath)}")
        console.print(f"[dim]   Kích thước: {self._format_size(self.file_size)}[/]")
        console.print()

        # Đọc file pcap với progress bar
        start_time = datetime.now()

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[bold green]{task.completed}/{task.total} packets"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                # Bước 1: Đọc raw packets
                task_load = progress.add_task("🔄 Đọc file pcap...", total=None)
                self.packets = rdpcap(filepath)
                progress.update(task_load, completed=len(self.packets), total=len(self.packets))

                # Bước 2: Parse từng packet
                task_parse = progress.add_task(
                    "🔍 Phân tích packets...", total=len(self.packets)
                )
                for pkt in self.packets:
                    parsed = self._parse_single_packet(pkt)
                    if parsed:
                        self.parsed_packets.append(parsed)
                    progress.advance(task_parse)

        except Exception as e:
            console.print(f"[bold red]❌ Lỗi khi đọc file pcap:[/] {str(e)}")
            console.print("[yellow]💡 Gợi ý: Đảm bảo file là định dạng .pcap/.pcapng hợp lệ[/]")
            sys.exit(1)

        self.load_time = (datetime.now() - start_time).total_seconds()

        console.print()
        console.print(f"[bold green]✅ Hoàn tất![/] Đã parse [bold]{len(self.parsed_packets)}[/]"
                       f"/{len(self.packets)} packets trong [bold]{self.load_time:.2f}s[/]")
        console.print()

        return self.parsed_packets

    def _parse_single_packet(self, packet):
        """
        Phân tích một packet, trích xuất thông tin chi tiết.

        Args:
            packet: Scapy packet object

        Returns:
            ParsedPacket hoặc None (nếu không có IP layer)
        """
        # Chỉ xử lý packet có IP layer
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        timestamp = float(packet.time)

        # Xác định protocol và trích xuất thông tin tương ứng
        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags = None
        is_syn = False
        is_http = False
        http_method = None
        http_uri = None
        raw_info = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = str(tcp_layer.flags)
            is_syn = "S" in tcp_flags and "A" not in tcp_flags  # SYN without ACK

            # Kiểm tra HTTP traffic (port 80, 8080, 443 hoặc payload HTTP)
            if dst_port in (80, 8080, 8000, 443) or src_port in (80, 8080, 8000, 443):
                is_http, http_method, http_uri = self._extract_http_info(packet)

            raw_info = f"TCP {src_port}->{dst_port} [{tcp_flags}]"

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            raw_info = f"UDP {src_port}->{dst_port}"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_layer = packet[ICMP]
            raw_info = f"ICMP type={icmp_layer.type} code={icmp_layer.code}"

        return ParsedPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            is_syn=is_syn,
            is_http=is_http,
            http_method=http_method,
            http_uri=http_uri,
            packet_size=packet_size,
            raw_info=raw_info,
        )

    def _extract_http_info(self, packet):
        """
        Trích xuất thông tin HTTP từ packet payload.

        Args:
            packet: Scapy packet object

        Returns:
            tuple: (is_http, method, uri)
        """
        if not packet.haslayer(Raw):
            return False, None, None

        try:
            payload = packet[Raw].load
            # Kiểm tra xem payload có bắt đầu bằng HTTP method không
            for method in self.HTTP_METHODS:
                if payload.startswith(method):
                    # Parse dòng đầu tiên: "GET /path HTTP/1.1"
                    first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                    parts = first_line.split(" ")
                    if len(parts) >= 2:
                        return True, parts[0], parts[1]
                    return True, method.decode(), "/"
            # Kiểm tra HTTP response
            if payload.startswith(b"HTTP/"):
                return True, "RESPONSE", None
        except Exception:
            pass

        return False, None, None

    def _format_size(self, size_bytes):
        """Format kích thước file cho dễ đọc."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    def get_summary(self):
        """
        Trả về thông tin tổng quan về file pcap đã load.

        Returns:
            dict: Thông tin tổng quan
        """
        if not self.parsed_packets:
            return {}

        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_size_formatted": self._format_size(self.file_size),
            "total_raw_packets": len(self.packets),
            "total_parsed_packets": len(self.parsed_packets),
            "load_time_seconds": self.load_time,
            "first_packet_time": self.parsed_packets[0].timestamp,
            "last_packet_time": self.parsed_packets[-1].timestamp,
            "capture_duration": self.parsed_packets[-1].timestamp - self.parsed_packets[0].timestamp,
        }
