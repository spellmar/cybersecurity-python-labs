"""Головний CLI-модуль для запуску Завдання 1 (demo) та Завдання 2 (analyze)."""

import argparse
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sys

from labs.lab02.task1 import Admin, AuditLog, Session, User, UserAccount
from labs.lab02.task2 import run_analysis

DEFAULT_AUTH_LOG = Path("labs/lab02/data/data_v04/auth.log")
DEFAULT_OUTPUT_JSON = Path("labs/lab02/data/blocklist_ips.json")


def configure_logging() -> None:
    """Налаштовує формат виведення повідомлень логування."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )


def run_demo() -> None:
    """Демонструє роботу моделей користувачів, сесій та журналу аудиту (Завдання 1)."""
    print("=== 1. Створення користувача та валідація email ===")
    user = User(username="alice", email="alice.sec@example.com", password="StrongPassword123")
    print(f"Створено: {user}")

    try:
        user.email = "invalid-email"
    except ValueError as err:
        print(f"Очікувана помилка валідації email: {err}")

    user.email = "alice.updated@cyber.ua"
    print(f"Оновлений email: {user.email}")

    print("\n=== 2. Робота з правами адміністратора (наслідування Admin -> User) ===")
    admin = Admin(
        username="root_admin",
        email="admin@cyber.ua",
        password="AdminSecretPassword",
        permissions=["read_logs"],
    )
    admin.grant_permission("ban_ip")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(f"Адміністратор: {admin}")
    print(f"Чи є право 'ban_ip': {admin.has_permission('ban_ip')}")

    print("\n=== 3. Аутентифікація, сесії та композиція (UserAccount) ===")
    audit = AuditLog()
    account = UserAccount(user=user, audit_log=audit)

    # Невдалий вхід
    login_bad = account.login("alice", "WrongPass", ip="198.51.100.44")
    print(f"Вхід з невірним паролем: {login_bad} | Авторизований: {account.is_authenticated()}")

    # Успішний вхід
    login_ok = account.login("alice", "StrongPassword123", ip="192.0.2.10")
    print(f"Вхід з вірним паролем: {login_ok} | Авторизований: {account.is_authenticated()}")
    print(f"Доступ через account['user']: {account['user'].username}")

    # Імітація завершення сеансу за таймаутом
    expired_time = datetime.now(timezone.utc) - timedelta(seconds=1000)
    account["session"] = Session(
        ip="192.0.2.10",
        login_time=expired_time,
        last_activity=expired_time,
    )
    print(f"Після 1000 сек неактивності (таймаут 900с): авторизований = {account.is_authenticated()}")

    # Повторний вхід та коректний вихід із системи (logout)
    account.login("alice", "StrongPassword123", ip="192.0.2.10")
    account.logout()
    print(f"Після logout(): авторизований = {account.is_authenticated()}")

    print("\n=== 4. Записи журналу аудиту (AuditLog) ===")
    account["audit_log"].show_all()


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2 (Варіант 4): ООП та аналізатор логів SSH."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Доступні режими роботи")

    # Підкоманда demo (Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію ООП-моделей (Завдання 1)")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser(
        "analyze", help="Проаналізувати журнал автентифікації SSH (Завдання 2)"
    )
    analyze_parser.add_argument(
        "--auth-log",
        type=Path,
        default=DEFAULT_AUTH_LOG,
        help=f"Шлях до файлу auth.log (за замовчуванням: {DEFAULT_AUTH_LOG})",
    )
    analyze_parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб входу для виявлення атаки (за замовчуванням: 5)",
    )
    analyze_parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Розмір часового вікна у хвилинах (за замовчуванням: 5)",
    )
    analyze_parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_OUTPUT_JSON,
        help=f"Шлях для збереження JSON-звіту (за замовчуванням: {DEFAULT_OUTPUT_JSON})",
    )

    return parser


def main() -> None:
    """Точка входу програми."""
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "demo":
            run_demo()
        elif args.command == "analyze":
            run_analysis(
                auth_log=args.auth_log,
                threshold=args.threshold,
                window_min=args.window_min,
                output_json=args.output_json,
            )
    except (FileNotFoundError, ValueError, TypeError, KeyError) as exc:
        logging.error("Помилка виконання: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()