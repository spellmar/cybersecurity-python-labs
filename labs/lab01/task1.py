# 1
import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "Security@2023",
    "pass",
    "MyStr0ng#Key",
    "root",
    "Advanc3d@Pass",
    "user",
    "Protec7!Pass",
    "1234",
    "Elite@Secur1ty",
    "admin123",
]
CRITERIA = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {"pass", "root", "user", "1234", "admin123", "password"}


def evaluate_password_strength(password: str, all_passwords: list) -> str:
    """Оцінює надійність пароля за заданими критеріями."""
    min_length = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    all_criteria_met = has_digit and has_upper and has_special

    if (
        all_criteria_met
        and len(password) >= min_length + 4
        and all_passwords.count(password) == 1
    ):
        return "Дуже сильний"

    if all_criteria_met and len(password) < min_length + 4:
        return "Сильний"

    if has_digit or has_upper or has_special or has_lower:
        if len(password) >= min_length:
            return "Середній"
        return "Слабкий"

    return "Слабкий"


def run_task1():
    print(
        f"=== Завдання 1 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант: {VARIANT_NUMBER} ==="
    )

    pwd_copy = list(PASSWORDS)
    random_indices = random.sample(range(len(pwd_copy)), 3)
    for idx in random_indices:
        pwd_copy.append(pwd_copy[idx])

    print("\nРезультати аналізу надійності паролів:")
    print("-" * 50)
    print(f"{'№':<3} | {'Пароль':<20} | {'Оцінка надійності':<15}")
    print("-" * 50)

    for i, pwd in enumerate(pwd_copy, 1):
        rating = evaluate_password_strength(pwd, pwd_copy)
        print(f"{i:<3} | {pwd:<20} | {rating:<15}")
    print("-" * 50)


if __name__ == "__main__":
    run_task1()
