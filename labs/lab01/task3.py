# 3
import csv
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    pass


MIN_PASSWORD_LEN = 14
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")

SALT = str(VARIANT_NUMBER).zfill(5)


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль та сіль не можуть бути порожніми!")

    if len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"Пароль закороткий! Мінімальна довжина: {MIN_PASSWORD_LEN}"
        )

    salted_password = (password + salt).encode("utf-8")
    return hashlib.sha512(salted_password).hexdigest()


def log_event(func):
    def wrapper(username, password, *args, **kwargs):
        result_status = "failure"
        try:
            res = func(username, password, *args, **kwargs)
            if res:
                result_status = "success"
            return res
        finally:
            os.makedirs(DATA_DIR, exist_ok=True)
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            logs = []
            if os.path.exists(LOG_JSON):
                try:
                    with open(LOG_JSON, "r", encoding="utf-8") as f:
                        logs = json.load(f)

                except (json.JSONDecodeError, OSError):
                    logs = []
            logs.append(log_entry)
            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username: str, password: str) -> tuple:
    hash_value = generate_hash(password, SALT)
    return (username, hash_value)


def create_users(users_list: list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "hash"])
        for user, pwd in users_list:
            try:
                u, h = create_user(user, pwd)
                writer.writerow([u, h])
            except (ValidationError, ValueError) as e:
                print(f"Помилка створення {user}: {e}")


def read_users_db() -> list:
    users_db = []
    with open(USERS_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
    return users_db


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми!")

    users_db = read_users_db()
    try:
        user_hash = generate_hash(password, SALT)
    except ValidationError:
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == user_hash:
            return True
    return False


def run_task3():
    print(
        f"=== Завдання 3 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант: {VARIANT_NUMBER} ==="
    )

    users_to_register = [
        ("user1", "SuperSecurePassword14!"),
        ("user2", "AnotherStrongPass2023!"),
        ("user3", "ShortPass1"),
        ("user4", "ValidPassword12345!"),
        ("user5", "Complex#Password#99"),
        ("user6", "MyPassphraseForLab1!"),
        ("user7", "CorrectHorseBattery"),
        ("user8", "CyberSecurity2023!"),
        ("user9", "VeryLongPasswordIndeed!"),
        ("user10", "FinalPassword12345!"),
    ]

    try:
        print("\nРеєстрація користувачів та збереження у CSV...")
        create_users(users_to_register)

        print("\nЗчитування бази даних CSV:")
        db = read_users_db()
        print("-" * 60)
        print(f"{'Логін':<15} | {'Хеш (sha512)':<40}")
        print("-" * 60)
        for u, h in db:
            print(f"{u:<15} | {h[:37]}...")
        print("-" * 60)

        print("\nТестування авторизації (входу):")
        print(
            "1. Вхід user1 (правильний пароль):",
            login("user1", "SuperSecurePassword14!"),
        )
        print(
            "2. Вхід user1 (неправильний пароль):",
            login("user1", "WrongPassword12345!"),
        )

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as e:
        print(f"Виняток оброблено: {e}")


if __name__ == "__main__":
    run_task3()
