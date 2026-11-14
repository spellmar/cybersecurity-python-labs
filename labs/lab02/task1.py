"""Модуль реалізації моделей користувачів, безпечних сесій та аудиту (Завдання 1)."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9._-]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


class User:
    """Базовий клас користувача системи з безпечним зберіганням пароля."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        """Ініціалізує об'єкт користувача."""
        if not username or not isinstance(username, str):
            raise ValueError("Ім'я користувача має бути непорожнім рядком.")
        self.username: str = username
        self.email = email
        self.role: str = role
        self.active: bool = active
        self.__password_salt: bytes = b""
        self.__password_hash: bytes = b""
        self.set_password(password)

    @property
    def email(self) -> str:
        """Повертає електронну пошту користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Перевіряє та встановлює електронну пошту користувача."""
        if not isinstance(value, str) or not EMAIL_PATTERN.match(value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        """Генерує сіль та зберігає PBKDF2-SHA256 хеш пароля."""
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має бути рядком довжиною щонайменше 4 символи.")
        self.__password_salt = os.urandom(SALT_BYTES)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє відповідність переданого пароля збереженому хешу."""
        if not isinstance(password, str) or not self.__password_hash:
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        """Повертає рядкове представлення користувача без конфіденційних даних."""
        status = "active" if self.active else "inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status={status})"
        )


class Admin(User):
    """Клас адміністратора, що розширює User списком дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        """Ініціалізує адміністратора та його права доступу."""
        super().__init__(
            username=username,
            email=email,
            password=password,
            role="admin",
            active=active,
        )
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає адміністратору вказаний дозвіл."""
        if not permission or not isinstance(permission, str):
            raise ValueError("Назва дозволу має бути непорожнім рядком.")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Відкликає вказаний дозвіл у адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність дозволу в адміністратора."""
        return permission in self.permissions

    def __str__(self) -> str:
        """Повертає інформацію про адміністратора та його права."""
        base_info = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        return f"{base_info} | permissions=[{perms}]"


class Session:
    """Клас сеансу роботи користувача з контролем часу неактивності (UTC)."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        """Ініціалізує сеанс із мітками часу в UTC."""
        now = datetime.now(UTC)
        self.ip: str = ip
        self.login_time: datetime = login_time if login_time is not None else now
        self.last_activity: datetime = (
            last_activity if last_activity is not None else self.login_time
        )

    def touch(self) -> None:
        """Оновлює час останньої активності поточним часом UTC."""
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевіряє, чи не перевищено час неактивності сеансу."""
        if not isinstance(timeout_sec, int) or timeout_sec <= 0:
            raise ValueError("Таймаут сеансу має бути додатним цілим числом.")
        now = datetime.now(UTC)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass
class AuditEntry:
    """Запис події в журналі аудиту безпеки."""

    username: str
    action: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __str__(self) -> str:
        """Форматує запис аудиту для виведення."""
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"[{ts}] user='{self.username}' | action='{self.action}'"


class AuditLog:
    """Журнал аудиту дій користувачів."""

    def __init__(self) -> None:
        """Ініціалізує порожній список записів."""
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис про подію до журналу."""
        self.entries.append(AuditEntry(username=username, action=action))

    def show_all(self) -> None:
        """Виводить усі записи журналу аудиту."""
        if not self.entries:
            print("Журнал аудиту порожній.")
            return
        for entry in self.entries:
            print(entry)


class UserAccount:
    """Обліковий запис, що поєднує користувача, сесію та журнал аудиту (композиція)."""

    _ALLOWED_KEYS = ("user", "session", "audit_log")

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Ініціалізує обліковий запис."""
        if not isinstance(user, User):
            raise TypeError("Атрибут 'user' має бути екземпляром класу User.")
        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Виконує автентифікацію користувача та створює сеанс при успіху."""
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевіряє наявність та актуальність поточного сеансу без його подовження."""
        if self.session is None or not self.user.active:
            return False
        return self.session.is_active(timeout_sec=timeout_sec)

    def logout(self) -> None:
        """Завершує активний сеанс і фіксує вихід у журналі аудиту."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        """Забезпечує словниковий доступ на читання до дозволених компонентів."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Забезпечує словниковий доступ на запис із перевіркою типів."""
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути об'єктом User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути об'єктом Session або None."
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення для 'audit_log' має бути об'єктом AuditLog.")
            self.audit_log = value
