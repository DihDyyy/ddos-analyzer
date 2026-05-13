# ============================================================================
# DDoS PCAP Analyzer - Main Entry Point
# ============================================================================
# Công cụ phân tích DDoS từ file .pcap (Wireshark)
# Phát hiện: SYN Flood, UDP Flood, ICMP Flood, HTTP Flood
# Hỗ trợ: Layer 3/4/7 | SOC/Blue Team
#
# Sử dụng: python main.py <file.pcap> [options]
# Xem help: python main.py --help
# ============================================================================

import argparse
import sys
import os
import time
import io

# Fix encoding cho Windows terminal
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Thêm thư mục hiện tại vào path để import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import config
from analyzer.packet_parser import PcapParser
from analyzer.statistics import TrafficStatistics
from analyzer.detector import DDoSDetector
from analyzer.dashboard import Dashboard
from analyzer.reporter import ReportGenerator

console = Console()


def print_welcome():
    """Hiển thị thông điệp chào mừng."""
    console.print()
    console.print(Panel(
        "[bold bright_cyan]DDoS PCAP Analyzer[/]\n"
        "[dim]Công cụ phân tích DDoS từ file .pcap | SOC/Blue Team[/]\n"
        f"[dim]Version {config.TOOL_VERSION}[/]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))


def create_parser():
    """Tạo argument parser cho CLI."""
    parser = argparse.ArgumentParser(
        prog="DDoS PCAP Analyzer",
        description=(
            "[DDoS PCAP Analyzer] Cong cu phan tich DDoS tu file .pcap (Wireshark)\n"
            "Phat hien SYN Flood, UDP Flood, ICMP Flood, HTTP Flood\n"
            "Ho tro phan tich Layer 3/4/7 | Thiet ke cho SOC/Blue Team"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Vi du su dung:\n"
            "  python main.py capture.pcap\n"
            "  python main.py capture.pcap --syn-threshold 50 --format json\n"
            "  python main.py capture.pcap --output-dir ./my_reports --top 20\n"
            "  python main.py capture.pcap --no-dashboard --format csv\n"
        ),
    )

    # Positional argument
    parser.add_argument(
        "pcap_file",
        help="Đường dẫn tới file .pcap/.pcapng cần phân tích",
    )

    # Ngưỡng phát hiện
    threshold_group = parser.add_argument_group("Nguong phat hien (packets/giay tu 1 IP)")
    threshold_group.add_argument(
        "--syn-threshold", type=int, default=config.SYN_FLOOD_THRESHOLD,
        help=f"Ngưỡng SYN Flood (mặc định: {config.SYN_FLOOD_THRESHOLD})",
    )
    threshold_group.add_argument(
        "--udp-threshold", type=int, default=config.UDP_FLOOD_THRESHOLD,
        help=f"Ngưỡng UDP Flood (mặc định: {config.UDP_FLOOD_THRESHOLD})",
    )
    threshold_group.add_argument(
        "--icmp-threshold", type=int, default=config.ICMP_FLOOD_THRESHOLD,
        help=f"Ngưỡng ICMP Flood (mặc định: {config.ICMP_FLOOD_THRESHOLD})",
    )
    threshold_group.add_argument(
        "--http-threshold", type=int, default=config.HTTP_FLOOD_THRESHOLD,
        help=f"Ngưỡng HTTP Flood (mặc định: {config.HTTP_FLOOD_THRESHOLD})",
    )

    # Hiển thị & Báo cáo
    output_group = parser.add_argument_group("Bao cao & Hien thi")
    output_group.add_argument(
        "--top", type=int, default=config.TOP_TALKERS_COUNT,
        help=f"Số lượng Top IP hiển thị (mặc định: {config.TOP_TALKERS_COUNT})",
    )
    output_group.add_argument(
        "--output-dir", type=str, default="reports",
        help="Thư mục xuất báo cáo (mặc định: ./reports)",
    )
    output_group.add_argument(
        "--format", type=str, default="all",
        choices=["json", "csv", "all"],
        help="Định dạng báo cáo: json, csv, hoặc all (mặc định: all)",
    )
    output_group.add_argument(
        "--no-dashboard", action="store_true",
        help="Không hiển thị CLI dashboard (chỉ xuất report)",
    )
    output_group.add_argument(
        "--no-report", action="store_true",
        help="Không xuất báo cáo (chỉ hiển thị dashboard)",
    )

    return parser


def main():
    """Hàm chính - điều phối toàn bộ quá trình phân tích."""
    parser = create_parser()
    args = parser.parse_args()

    # Hiển thị welcome
    print_welcome()

    # Cập nhật config từ arguments
    config.SYN_FLOOD_THRESHOLD = args.syn_threshold
    config.UDP_FLOOD_THRESHOLD = args.udp_threshold
    config.ICMP_FLOOD_THRESHOLD = args.icmp_threshold
    config.HTTP_FLOOD_THRESHOLD = args.http_threshold
    config.TOP_TALKERS_COUNT = args.top

    # Hiển thị cấu hình ngưỡng
    console.print(Panel(
        f"[bold]🎯 Ngưỡng phát hiện (packets/giây):[/]\n"
        f"  SYN Flood  : [cyan]{args.syn_threshold}[/]\n"
        f"  UDP Flood  : [magenta]{args.udp_threshold}[/]\n"
        f"  ICMP Flood : [yellow]{args.icmp_threshold}[/]\n"
        f"  HTTP Flood : [green]{args.http_threshold}[/]\n"
        f"  Top IPs    : [white]{args.top}[/]",
        title="[bold white]⚙️ CẤU HÌNH[/]",
        border_style="dim",
        padding=(1, 2),
    ))

    # ─────────────────────────────────────────────────────────────────
    # BƯỚC 1: Đọc và parse file pcap
    # ─────────────────────────────────────────────────────────────────
    console.print("[bold bright_blue]━━━ BƯỚC 1/4: Đọc file PCAP ━━━[/]")

    pcap_parser = PcapParser()
    parsed_packets = pcap_parser.load_pcap(args.pcap_file)
    parser_summary = pcap_parser.get_summary()

    if not parsed_packets:
        console.print("[bold red]❌ Không tìm thấy packet IP nào trong file![/]")
        console.print("[yellow]💡 Gợi ý: File pcap có thể trống hoặc chỉ chứa traffic non-IP[/]")
        sys.exit(1)

    # ─────────────────────────────────────────────────────────────────
    # BƯỚC 2: Tính toán thống kê
    # ─────────────────────────────────────────────────────────────────
    console.print("[bold bright_blue]━━━ BƯỚC 2/4: Phân tích thống kê ━━━[/]")

    statistics = TrafficStatistics(parsed_packets, time_window=config.TIME_WINDOW)
    console.print("[green]✅ Đã tính toán thống kê traffic[/]")

    # ─────────────────────────────────────────────────────────────────
    # BƯỚC 3: Phát hiện DDoS
    # ─────────────────────────────────────────────────────────────────
    console.print("[bold bright_blue]━━━ BƯỚC 3/4: Phát hiện DDoS ━━━[/]")

    thresholds = {
        "SYN_FLOOD": args.syn_threshold,
        "UDP_FLOOD": args.udp_threshold,
        "ICMP_FLOOD": args.icmp_threshold,
        "HTTP_FLOOD": args.http_threshold,
    }

    detector = DDoSDetector(statistics, thresholds=thresholds)
    alerts = detector.run_all_detections()

    risk_level = detector.get_overall_risk_level()
    severity_colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold blue",
        "SAFE": "bold green",
    }
    risk_color = severity_colors.get(risk_level, "white")

    console.print(f"[green]✅ Hoàn tất phát hiện:[/] "
                  f"[bold]{len(alerts)}[/] cảnh báo | "
                  f"Mức rủi ro: [{risk_color}]{risk_level}[/]")

    # Cảnh báo real-time trên terminal
    if alerts:
        console.print()
        console.print("[bold red]🚨 CẢNH BÁO REAL-TIME:[/]")
        # Hiển thị tối đa 5 cảnh báo nghiêm trọng nhất
        for alert in alerts[:5]:
            color = severity_colors.get(alert.severity, "white")
            console.print(
                f"  [{color}][{alert.severity}][/] "
                f"{alert.attack_type} từ [bold]{alert.source_ip}[/] "
                f"| {alert.packet_count} pkts/s "
                f"({alert.ratio}x ngưỡng)"
            )
        if len(alerts) > 5:
            console.print(f"  [dim]... và {len(alerts) - 5} cảnh báo khác[/]")
    console.print()

    # ─────────────────────────────────────────────────────────────────
    # BƯỚC 4: Dashboard & Báo cáo
    # ─────────────────────────────────────────────────────────────────
    console.print("[bold bright_blue]━━━ BƯỚC 4/4: Kết quả ━━━[/]")

    # Hiển thị Dashboard
    if not args.no_dashboard:
        dashboard = Dashboard()
        dashboard.render(parser_summary, statistics, detector, alerts)

    # Xuất báo cáo
    if not args.no_report:
        reporter = ReportGenerator(parser_summary, statistics, detector)

        if args.format == "json":
            reporter.generate_json(args.output_dir)
        elif args.format == "csv":
            reporter.generate_csv(args.output_dir)
        else:
            reporter.generate_all(args.output_dir)

    console.print()
    console.print(Panel(
        f"[bold green]🎉 Phân tích hoàn tất![/]\n\n"
        f"  📦 Packets phân tích : [bold]{len(parsed_packets):,}[/]\n"
        f"  🚨 Cảnh báo DDoS    : [bold]{len(alerts)}[/]\n"
        f"  🛡️  Mức rủi ro       : [{risk_color}]{risk_level}[/]\n"
        f"  📁 Báo cáo           : [dim]{os.path.abspath(args.output_dir) if not args.no_report else 'Không xuất'}[/]",
        title="[bold white]✅ KẾT QUẢ[/]",
        border_style="bright_green",
        padding=(1, 2),
    ))


if __name__ == "__main__":
    main()
