# 2
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "ciso_office": {
        "role": "ciso",
        "clearance": 4,
        "department": "Executive",
        "active": True,
    },
    "threat_hunter": {
        "role": "threat_analyst",
        "clearance": 3,
        "department": "Threat Intel",
        "active": True,
    },
    "junior_dev": {
        "role": "junior_developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "visitor_acc": {
        "role": "visitor",
        "clearance": 1,
        "department": "Guest",
        "active": True,
    },
    "legacy_sys": {
        "role": "legacy",
        "clearance": 2,
        "department": "Legacy",
        "active": False,
    },
}

RESOURCES = [
    ("threat_intelligence", 4),
    ("malware_samples", 3),
    ("coding_guidelines", 2),
    ("visitor_wifi", 1),
    ("strategic_plans", 4),
    ("demo_environment", 1),
    ("risk_assessments", 3),
    ("crypto_keys", 4),
    ("api_documentation", 2),
    ("guest_portal", 1),
]

SECURITY_LEVELS = ("Guest", "Employee", "Privileged", "Executive")
BLOCKED_USERS = {"legacy_sys", "malicious_user", "expired_guest"}


def check_access(username: str, resource_name: str, resource_level: int) -> tuple:
    if username not in USERS:
        return "DENY", "User not found"

    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user_data = USERS[username]
    if not user_data.get("active", False):
        return "DENY", "Account inactive"

    if user_data["clearance"] >= resource_level:
        return "ALLOW", ""
    else:
        return "DENY", "Insufficient clearance"


def run_task2():
    print(
        f"=== Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант: {VARIANT_NUMBER} ==="
    )

    print("\nСписок ресурсів системи:")
    print("-" * 50)
    for res_name, level in RESOURCES:
        level_label = SECURITY_LEVELS[level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень безпеки: {level_label}")
    print("-" * 50)

    print("\nРезультати перевірки доступу:")
    test_users = list(USERS.keys()) + ["unknown_user", "malicious_user"]

    for user in test_users:
        for res_name, res_level in RESOURCES[:2]:
            status, reason = check_access(user, res_name, res_level)
            reason_str = f" ({reason})" if reason else ""
            print(f"user=[{user}] resource=[{res_name}] -> {status}{reason_str}")


if __name__ == "__main__":
    run_task2()
