# ============================================================================
# DDoS PCAP Analyzer - CLI Dashboard Module
# ============================================================================
# Hiển thị dashboard trực quan trên terminal sử dụng Rich library
# Bao gồm: Traffic Overview, Protocol Distribution, Top IPs,
# Packet Rate, Alerts, Attack Summary
# ============================================================================

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box

import config


class Dashboard:
    """
    CLI Dashboard hiển thị kết quả phân tích DDoS.
    Sử dụng Rich library cho giao diện terminal trực quan.
    """

    # Bảng màu severity
    SEVERITY_COLORS = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold blue",
        "SAFE": "bold green",
    }

    # Bảng màu protocol
    PROTOCOL_COLORS = {
        "TCP": "cyan",
        "UDP": "magenta",
        "ICMP": "yellow",
        "HTTP": "green",
        "OTHER": "dim white",
    }

    # Ký tự cho bar chart
    BAR_CHARS = "▏▎▍▌▋▊▉█"
    SPARK_CHARS = "▁▂▃▄▅▆▇█"

    def __init__(self):
        self.console = Console()

    def render(self, parser_summary, statistics, detector, alerts):
        """
        Render toàn bộ dashboard.

        Args:
            parser_summary (dict): Thông tin file pcap
            statistics (TrafficStatistics): Object thống kê
            detector (DDoSDetector): Object phát hiện
            alerts (list[Alert]): Danh sách cảnh báo
        """
        self.console.print()
        self._render_banner()
        self._render_file_info(parser_summary)
        self._render_traffic_overview(statistics)
        self._render_protocol_distribution(statistics)
        self._render_packet_rate(statistics)
        self._render_top_source_ips(statistics)
        self._render_http_stats(statistics)
        self._render_alerts(alerts)
        self._render_attack_summary(detector)
        self._render_risk_assessment(detector)
        self._render_footer()

    def _render_banner(self):
        """Hiển thị banner ASCII art."""
        banner_text = """
 ██████╗ ██████╗  ██████╗ ███████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
 ██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██║  ██║██║  ██║██║   ██║███████╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██║  ██║██║  ██║██║   ██║╚════██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ██████╔╝██████╔╝╚██████╔╝███████║    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝"""

        self.console.print(Panel(
            Text(banner_text, style="bold cyan"),
            subtitle=f"[dim]v{config.TOOL_VERSION} | {config.TOOL_AUTHOR} | Phân tích DDoS từ file PCAP[/dim]",
            border_style="bright_cyan",
            padding=(0, 1),
        ))

    def _render_file_info(self, summary):
        """Hiển thị thông tin file pcap."""
        if not summary:
            return

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Key", style="bold white")
        info_table.add_column("Value", style="bright_white")

        info_table.add_row("📁 File", summary.get("file_path", "N/A"))
        info_table.add_row("📐 Kích thước", summary.get("file_size_formatted", "N/A"))
        info_table.add_row("📦 Tổng packets (raw)", str(summary.get("total_raw_packets", 0)))
        info_table.add_row("✅ Packets đã parse", str(summary.get("total_parsed_packets", 0)))
        info_table.add_row("⏱️ Thời gian load", f"{summary.get('load_time_seconds', 0):.2f}s")

        duration = summary.get("capture_duration", 0)
        if duration > 0:
            info_table.add_row("⏳ Thời lượng capture", f"{duration:.2f}s")

        self.console.print(Panel(
            info_table,
            title="[bold white]📂 THÔNG TIN FILE PCAP[/]",
            border_style="blue",
            padding=(1, 2),
        ))

    def _render_traffic_overview(self, statistics):
        """Hiển thị tổng quan traffic."""
        capture_info = statistics.get_capture_info()
        if not capture_info:
            return

        packet_rate = statistics.get_packet_rate()

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="bold white", width=30)
        table.add_column("Value", style="bright_green", justify="right")

        table.add_row("📦 Tổng Packets", f"{capture_info['total_packets']:,}")
        table.add_row("📊 Tổng Dữ liệu", capture_info["total_bytes_formatted"])
        table.add_row("📐 Avg Packet Size", f"{capture_info['avg_packet_size']} bytes")
        table.add_row("🌐 Unique Source IPs", str(capture_info["unique_src_ips"]))
        table.add_row("🎯 Unique Dest IPs", str(capture_info["unique_dst_ips"]))
        table.add_row("🔌 Unique Dest Ports", str(capture_info["unique_dst_ports"]))
        table.add_row("⚡ Avg PPS", f"{packet_rate['avg_pps']:,.1f} pkt/s")
        table.add_row("🔥 Max PPS", f"[bold red]{packet_rate['max_pps']:,}[/] pkt/s")
        table.add_row("🕐 Bắt đầu", capture_info["start_time"])
        table.add_row("🕐 Kết thúc", capture_info["end_time"])
        table.add_row("⏳ Thời lượng", f"{capture_info['capture_duration_seconds']}s")

        self.console.print(Panel(
            table,
            title="[bold white]📊 TỔNG QUAN TRAFFIC[/]",
            border_style="green",
            padding=(1, 2),
        ))

    def _render_protocol_distribution(self, statistics):
        """Hiển thị phân bố giao thức với bar chart."""
        distribution = statistics.get_protocol_distribution()
        if not distribution:
            return

        table = Table(
            title="",
            box=box.ROUNDED,
            show_lines=True,
            border_style="bright_blue",
            header_style="bold white on dark_blue",
        )
        table.add_column("Protocol", style="bold", width=10, justify="center")
        table.add_column("Count", justify="right", width=12)
        table.add_column("Percentage", justify="right", width=10)
        table.add_column("Distribution", width=40)

        max_count = max(d["count"] for d in distribution.values()) if distribution else 1

        for proto, data in distribution.items():
            color = self.PROTOCOL_COLORS.get(proto, "white")
            bar_length = int((data["count"] / max_count) * 35)
            bar = "█" * bar_length + "░" * (35 - bar_length)

            table.add_row(
                f"[{color}]{proto}[/]",
                f"[{color}]{data['count']:,}[/]",
                f"[{color}]{data['percentage']}%[/]",
                f"[{color}]{bar}[/]",
            )

        self.console.print(Panel(
            table,
            title="[bold white]🔬 PHÂN BỐ GIAO THỨC[/]",
            border_style="bright_blue",
            padding=(1, 2),
        ))

    def _render_packet_rate(self, statistics):
        """Hiển thị biểu đồ packet rate theo thời gian."""
        packet_rate = statistics.get_packet_rate()
        timeline = packet_rate.get("timeline", [])

        if not timeline:
            return

        # Tạo sparkline chart
        max_val = max(timeline) if timeline else 1
        if max_val == 0:
            max_val = 1

        # Giới hạn hiển thị tối đa 80 cột
        display_timeline = timeline
        if len(timeline) > 80:
            # Gộp các khoảng thời gian
            step = len(timeline) // 80
            display_timeline = []
            for i in range(0, len(timeline), step):
                chunk = timeline[i:i + step]
                display_timeline.append(max(chunk))

        spark = ""
        for val in display_timeline:
            idx = int((val / max_val) * (len(self.SPARK_CHARS) - 1))
            char = self.SPARK_CHARS[idx]
            # Tô màu theo mức độ
            if val / max_val > 0.8:
                spark += f"[bold red]{char}[/]"
            elif val / max_val > 0.5:
                spark += f"[yellow]{char}[/]"
            elif val / max_val > 0.2:
                spark += f"[green]{char}[/]"
            else:
                spark += f"[dim cyan]{char}[/]"

        content = Text()
        stats_line = (f"  Avg: [bold green]{packet_rate['avg_pps']:,.1f}[/] pkt/s  │  "
                      f"Max: [bold red]{packet_rate['max_pps']:,}[/] pkt/s  │  "
                      f"Min: [bold cyan]{packet_rate['min_pps']:,}[/] pkt/s  │  "
                      f"Intervals: [bold]{len(timeline)}[/]")

        self.console.print(Panel(
            f"{spark}\n\n{stats_line}",
            title="[bold white]⚡ PACKET RATE TIMELINE (PPS)[/]",
            subtitle="[dim]█ High  ▅ Medium  ▂ Low  ▁ Minimal[/]",
            border_style="yellow",
            padding=(1, 2),
        ))

    def _render_top_source_ips(self, statistics):
        """Hiển thị bảng top source IPs."""
        top_ips = statistics.get_top_source_ips(config.TOP_TALKERS_COUNT)
        if not top_ips:
            return

        table = Table(
            box=box.ROUNDED,
            show_lines=True,
            border_style="bright_magenta",
            header_style="bold white on purple",
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Source IP", style="bold bright_white", width=18)
        table.add_column("Packets", justify="right", width=10)
        table.add_column("% Total", justify="right", width=8)
        table.add_column("Protocols", width=30)
        table.add_column("Risk", justify="center", width=10)

        for i, ip_data in enumerate(top_ips, 1):
            # Protocol breakdown
            proto_parts = []
            for proto, count in sorted(ip_data["protocols"].items(), key=lambda x: -x[1]):
                color = self.PROTOCOL_COLORS.get(proto, "white")
                proto_parts.append(f"[{color}]{proto}:{count}[/]")
            proto_str = " | ".join(proto_parts)

            # Risk indicator
            pct = ip_data["percentage"]
            if pct > 50:
                risk = "[bold red]⚠ CRITICAL[/]"
            elif pct > 25:
                risk = "[red]🔴 HIGH[/]"
            elif pct > 10:
                risk = "[yellow]🟡 MEDIUM[/]"
            else:
                risk = "[green]🟢 LOW[/]"

            rank_style = "bold yellow" if i <= 3 else "dim"
            table.add_row(
                f"[{rank_style}]{i}[/]",
                ip_data["ip"],
                f"{ip_data['count']:,}",
                f"{ip_data['percentage']}%",
                proto_str,
                risk,
            )

        self.console.print(Panel(
            table,
            title="[bold white]🏆 TOP SOURCE IPs (Potential Attackers)[/]",
            border_style="bright_magenta",
            padding=(1, 2),
        ))

    def _render_http_stats(self, statistics):
        """Hiển thị thống kê HTTP."""
        http_stats = statistics.get_http_stats()
        if not http_stats or http_stats["total_requests"] == 0:
            return

        # HTTP Methods table
        method_table = Table(box=box.SIMPLE, border_style="green", show_lines=False)
        method_table.add_column("Method", style="bold green", width=10)
        method_table.add_column("Count", justify="right", width=10)

        for method, count in sorted(http_stats["methods"].items(), key=lambda x: -x[1]):
            method_table.add_row(method, f"{count:,}")

        # Top URIs table
        uri_table = Table(box=box.SIMPLE, border_style="cyan", show_lines=False)
        uri_table.add_column("URI", style="bold cyan", width=40, no_wrap=True)
        uri_table.add_column("Count", justify="right", width=10)

        for uri_data in http_stats["top_uris"][:5]:
            uri_table.add_row(uri_data["uri"][:40], f"{uri_data['count']:,}")

        content_parts = [
            f"[bold]📊 Tổng HTTP Requests:[/] [green]{http_stats['total_requests']:,}[/]\n",
        ]

        self.console.print(Panel(
            Columns([
                Panel(method_table, title="[bold]HTTP Methods[/]", border_style="green", width=25),
                Panel(uri_table, title="[bold]Top URIs[/]", border_style="cyan"),
            ]),
            title="[bold white]🌐 HTTP TRAFFIC (Layer 7)[/]",
            border_style="bright_green",
            padding=(1, 2),
        ))

    def _render_alerts(self, alerts):
        """Hiển thị bảng cảnh báo DDoS."""
        self.console.print(Rule("[bold red]🚨 CẢNH BÁO DDoS[/]", style="red"))
        self.console.print()

        if not alerts:
            self.console.print(Panel(
                "[bold green]✅ KHÔNG PHÁT HIỆN TẤN CÔNG DDoS NÀO[/]\n\n"
                "[dim]Không có traffic nào vượt ngưỡng phát hiện. File pcap này có vẻ an toàn.[/]",
                border_style="green",
                padding=(1, 2),
            ))
            return

        # Hiển thị số lượng alerts
        self.console.print(
            f"  [bold red]⚠ Phát hiện {len(alerts)} cảnh báo DDoS![/]\n"
        )

        # Bảng alerts
        table = Table(
            box=box.HEAVY,
            show_lines=True,
            border_style="red",
            header_style="bold white on dark_red",
        )
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Attack Type", width=25)
        table.add_column("Source IP", style="bold", width=18)
        table.add_column("Time Slot", justify="center", width=10)
        table.add_column("Packets/s", justify="right", width=10)
        table.add_column("Threshold", justify="right", width=10)
        table.add_column("Ratio", justify="right", width=8)

        # Giới hạn hiển thị 50 alerts trên dashboard
        display_alerts = alerts[:50]

        for alert in display_alerts:
            severity_style = self.SEVERITY_COLORS.get(alert.severity, "white")

            # Icon theo severity
            severity_icons = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
            }
            severity_icon = severity_icons.get(alert.severity, "⚪")

            # Attack type display
            attack_names = {
                "SYN_FLOOD": "SYN Flood (L4)",
                "UDP_FLOOD": "UDP Flood (L4)",
                "ICMP_FLOOD": "ICMP Flood (L3)",
                "HTTP_FLOOD": "HTTP Flood (L7)",
            }

            table.add_row(
                f"[{severity_style}]{severity_icon} {alert.severity}[/]",
                attack_names.get(alert.attack_type, alert.attack_type),
                alert.source_ip,
                f"t={alert.time_slot}s",
                f"[bold]{alert.packet_count:,}[/]",
                str(alert.threshold),
                f"[{severity_style}]{alert.ratio}x[/]",
            )

        self.console.print(table)

        if len(alerts) > 50:
            self.console.print(
                f"\n  [dim]... và {len(alerts) - 50} cảnh báo khác (xem trong report)[/]"
            )

    def _render_attack_summary(self, detector):
        """Hiển thị tổng kết tấn công."""
        summary = detector.get_alert_summary()
        if not summary:
            return

        self.console.print()

        table = Table(
            box=box.ROUNDED,
            show_lines=True,
            border_style="bright_red",
            header_style="bold white on dark_red",
            title="",
        )
        table.add_column("Attack Type", width=25)
        table.add_column("Layer", justify="center", width=8)
        table.add_column("Alerts", justify="right", width=8)
        table.add_column("Unique IPs", justify="right", width=10)
        table.add_column("Max PPS", justify="right", width=10)
        table.add_column("Severity", justify="center", width=12)

        layer_map = {
            "SYN_FLOOD": "L4",
            "UDP_FLOOD": "L4",
            "ICMP_FLOOD": "L3",
            "HTTP_FLOOD": "L7",
        }

        for attack_type, data in summary.items():
            severity_style = self.SEVERITY_COLORS.get(data["max_severity"], "white")
            table.add_row(
                data["display_name"],
                layer_map.get(attack_type, "?"),
                str(data["total_alerts"]),
                str(data["unique_source_ips"]),
                f"{data['max_packets_per_second']:,}",
                f"[{severity_style}]{data['max_severity']}[/]",
            )

        self.console.print(Panel(
            table,
            title="[bold white]📋 TỔNG KẾT TẤN CÔNG[/]",
            border_style="bright_red",
            padding=(1, 2),
        ))

    def _render_risk_assessment(self, detector):
        """Hiển thị đánh giá rủi ro tổng thể."""
        risk = detector.get_overall_risk_level()
        color = self.SEVERITY_COLORS.get(risk, "white")

        risk_messages = {
            "CRITICAL": "🔴 NGUY HIỂM - Phát hiện nhiều dấu hiệu tấn công DDoS nghiêm trọng!",
            "HIGH": "🟠 CAO - Phát hiện dấu hiệu tấn công DDoS đáng lo ngại!",
            "MEDIUM": "🟡 TRUNG BÌNH - Phát hiện traffic bất thường, có thể là tấn công DDoS.",
            "LOW": "🔵 THẤP - Có một số traffic bất thường nhưng chưa nghiêm trọng.",
            "SAFE": "🟢 AN TOÀN - Không phát hiện dấu hiệu tấn công DDoS.",
        }

        risk_recommendations = {
            "CRITICAL": [
                "• Kiểm tra ngay các IP nguồn tấn công và cân nhắc block",
                "• Kiểm tra log firewall và IDS/IPS",
                "• Thông báo đội ngũ SOC/Incident Response",
                "• Xem xét kích hoạt DDoS mitigation",
            ],
            "HIGH": [
                "• Theo dõi chặt chẽ các IP nguồn bất thường",
                "• Kiểm tra quy tắc firewall",
                "• Chuẩn bị kế hoạch ứng phó",
            ],
            "MEDIUM": [
                "• Tiếp tục giám sát traffic",
                "• Kiểm tra lại ngưỡng phát hiện",
                "• Xác nhận xem có phải traffic hợp lệ không",
            ],
            "LOW": [
                "• Ghi nhận và theo dõi",
                "• Kiểm tra lại cấu hình ngưỡng",
            ],
            "SAFE": [
                "• Tiếp tục giám sát định kỳ",
                "• Traffic trong ngưỡng bình thường",
            ],
        }

        message = risk_messages.get(risk, "Không xác định")
        recommendations = risk_recommendations.get(risk, [])
        rec_text = "\n".join(recommendations)

        self.console.print(Panel(
            f"[{color}]{message}[/]\n\n"
            f"[bold white]📝 Khuyến nghị:[/]\n{rec_text}",
            title=f"[bold white]🛡️ ĐÁNH GIÁ RỦI RO TỔNG THỂ: [{color}]{risk}[/][/]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))

    def _render_footer(self):
        """Hiển thị footer."""
        self.console.print()
        self.console.print(Rule(style="dim"))
        self.console.print(
            f"[dim]  {config.TOOL_NAME} v{config.TOOL_VERSION} | "
            f"{config.TOOL_AUTHOR} | "
            f"Sử dụng Scapy + Rich | "
            f"Phân tích DDoS Layer 3/4/7[/]"
        )
        self.console.print()
