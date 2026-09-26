import hashlib
import re
import socket


def extract_ip(log_line: str) -> str | None:
    """Извлекает IPv4-адрес из строки с неудачной SSH-аутентификацией."""
    if not log_line or "Failed password" not in log_line:
        return None

    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", log_line)
    if not match:
        return None

    ip = match.group(1)
    parts = ip.split(".")
    if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return ip
    return None


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """Подсчитывает количество неудачных SSH-входов для каждого IP."""
    result: dict[str, int] = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip is not None:
            result[ip] = result.get(ip, 0) + 1
    return result


def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """Возвращает IP, у которых число неудачных попыток >= threshold."""
    return [ip for ip, count in ip_counts.items() if count >= threshold]


def detect_suspicious_paths(log_line: str) -> bool:
    """Проверяет веб-лог на известные сигнатуры подозрительных запросов."""
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php",
    ]
    line = log_line.lower()
    return any(signature in line for signature in signatures)


def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """Рассчитывает уровень риска LOW / MEDIUM / HIGH."""
    score = brute_force_alerts * 3 + web_alerts
    if score == 0:
        return "LOW"
    if score < 5:
        return "MEDIUM"
    return "HIGH"


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Проверяет, доступен ли TCP-порт."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except (OSError, ValueError):
        return False


def get_file_hash(filepath: str) -> str:
    """Вычисляет SHA-256 файла. Если файла нет — FILE_NOT_FOUND."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    return sha256.hexdigest()
