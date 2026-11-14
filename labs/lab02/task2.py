"""Консольна утиліта аналізу логів автентифікації SSH (Варіант 4)."""

import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


@dataclass
class AuthEvent:
    """Подія автентифікації зі стандартного журналу SSH."""

    timestamp: datetime
    status: str
    username: str
    ip: str


@dataclass
class BruteforceAlert:
    """Інформація про виявлену атаку підбору паролів (Bruteforce)."""

    ip: str
    total_failures: int
    max_in_window: int
    window_minutes: int
    target_users: list[str]
    first_seen: str
    last_seen: str


def parse_auth_log(log_path: Path, year: int = 2026) -> tuple[list[AuthEvent], int]:
    """Зчитує та розбирає події Failed/Accepted password із файлу auth.log."""
    if not log_path.exists() or not log_path.is_file():
        raise FileNotFoundError(f"Файл журналу не знайдено: {log_path}")

    events: list[AuthEvent] = []
    total_lines = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            total_lines += 1
            match = LOG_PATTERN.search(line.strip())
            if not match:
                continue

            raw_ts = f"{year} {match.group('month')} {match.group('day')} {match.group('time')}"
            try:
                parsed_ts = datetime.strptime(raw_ts, "%Y %b %d %H:%M:%S")
            except ValueError:
                continue

            events.append(
                AuthEvent(
                    timestamp=parsed_ts,
                    status=match.group("status"),
                    username=match.group("user"),
                    ip=match.group("ip"),
                )
            )

    return events, total_lines


def detect_bruteforce(
    events: list[AuthEvent],
    threshold: int = 5,
    window_min: int = 5,
) -> list[BruteforceAlert]:
    """Виявляє IP-адреси, що перевищили поріг невдалих спроб у заданому часовому вікні."""
    if threshold <= 0:
        raise ValueError("Поріг спроб (--threshold) має бути додатним числом.")
    if window_min <= 0:
        raise ValueError("Часове вікно (--window-min) має бути додатним числом.")

    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.status == "Failed":
            failures_by_ip[event.ip].append(event)

    alerts: list[BruteforceAlert] = []
    window_delta = timedelta(minutes=window_min)

    for ip, ip_events in failures_by_ip.items():
        ip_events.sort(key=lambda item: item.timestamp)
        sliding_window: deque[datetime] = deque()
        max_in_window = 0

        for item in ip_events:
            sliding_window.append(item.timestamp)
            while (
                sliding_window and (item.timestamp - sliding_window[0]) > window_delta
            ):
                sliding_window.popleft()
            max_in_window = max(max_in_window, len(sliding_window))

        if max_in_window > threshold or len(ip_events) > threshold:
            target_users = sorted({item.username for item in ip_events})
            alerts.append(
                BruteforceAlert(
                    ip=ip,
                    total_failures=len(ip_events),
                    max_in_window=max_in_window,
                    window_minutes=window_min,
                    target_users=target_users,
                    first_seen=ip_events[0].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen=ip_events[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                )
            )

    alerts.sort(key=lambda alert: alert.total_failures, reverse=True)
    return alerts


def run_analysis(
    auth_log: Path,
    threshold: int = 5,
    window_min: int = 5,
    output_json: Path | None = None,
) -> list[BruteforceAlert]:
    """Виконує повний цикл аналізу SSH-логу, виводить звіт та експортує JSON."""
    logger.info("Analyzing authentication events in %s...", auth_log)
    events, total_lines = parse_auth_log(auth_log)

    if events:
        start_ts = min(e.timestamp for e in events).strftime("%Y-%m-%d %H:%M:%S")
        end_ts = max(e.timestamp for e in events).strftime("%Y-%m-%d %H:%M:%S")
        logger.info(
            "Processed %d lines (Time range: %s - %s)", total_lines, start_ts, end_ts
        )
    else:
        logger.info("Processed %d lines (No valid SSH auth events found)", total_lines)

    alerts = detect_bruteforce(events, threshold=threshold, window_min=window_min)

    print("\n=== SSH Bruteforce Detection Results ===")
    print(f"Failed Attempts Threshold: >{threshold} attempts in {window_min} minutes")

    if not alerts:
        print("No bruteforce attacks detected.")
    else:
        for alert in alerts:
            users_str = ", ".join(alert.target_users)
            logger.error(
                "Bruteforce Detected! IP: %s | Total Failures: %d | Max in %d min: %d | Target Users: %s",
                alert.ip,
                alert.total_failures,
                alert.window_minutes,
                alert.max_in_window,
                users_str,
            )

    blocklist = [alert.ip for alert in alerts]
    print("\n=== Recommended Blocklist (IPs) ===")
    if blocklist:
        for ip in blocklist:
            print(ip)
    else:
        print("None")

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "source_log": str(auth_log),
            "threshold": threshold,
            "window_minutes": window_min,
            "total_lines_processed": total_lines,
            "matched_events": len(events),
            "blocklist_ips": blocklist,
            "alerts": [asdict(alert) for alert in alerts],
        }
        with output_json.open("w", encoding="utf-8") as out_file:
            json.dump(report_data, out_file, indent=4, ensure_ascii=False)
        logger.info("Exported blocklist to %s", output_json)

    return alerts
