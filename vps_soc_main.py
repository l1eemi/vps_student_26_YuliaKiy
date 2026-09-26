import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py")
    sys.exit(1)


def find_nginx_log() -> str | None:
    possible_paths = [
        os.path.expanduser("~/logs/access.log"),
        os.path.expanduser("~/logs/nginx_access.log"),
        os.path.expanduser("~/logs/nginx/access.log"),
        "/var/log/nginx/access.log",
    ]
    for path in possible_paths:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path
    return None


def run_pipeline() -> None:
    print("=" * 60)
    print("МИНИ-SOC: АНАЛИЗ РЕАЛЬНЫХ ЛОГОВ VPS")
    print("=" * 60)

    ssh_log_path = os.path.expanduser("~/logs/auth.log")
    print("[1] Источники данных")
    print(f" - SSH лог: {ssh_log_path}")

    if not os.path.isfile(ssh_log_path):
        print(f"[!] SSH лог не найден: {ssh_log_path}")
        print("[!] Проверь командой: ls -lh ~/logs/auth.log")
        return

    nginx_log_path = find_nginx_log()
    if nginx_log_path:
        print(f" - Nginx лог: {nginx_log_path}")
    else:
        print(" - Nginx access.log не найден. Веб-анализ будет пропущен.")
    print("-" * 60)

    print("[2] Анализ SSH логов")
    try:
        with open(ssh_log_path, "r", encoding="utf-8", errors="ignore") as file:
            ssh_logs = file.readlines()
    except PermissionError:
        print(f"[!] Нет прав на чтение {ssh_log_path}")
        return

    ip_attempts = analyzer.group_by_ip(ssh_logs)
    print(f" - Всего строк: {len(ssh_logs)}")
    print(f" - Уникальных IP с неудачными входами: {len(ip_attempts)}")

    for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True)[:10]:
        print(f" * {ip}: {count} неудачных попыток")

    bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)
    print(f" - ОБНАРУЖЕНО BRUTE-FORCE IP (>= 5 попыток): {len(bf_alerts)}")
    for ip in bf_alerts:
        print(f" [ALERT] {ip}: {ip_attempts[ip]} неудачных попыток")
    print("-" * 60)

    print("[3] Анализ веб-логов")
    web_alerts_count = 0
    if nginx_log_path:
        try:
            with open(nginx_log_path, "r", encoding="utf-8", errors="ignore") as file:
                nginx_logs = file.readlines()
            for line in nginx_logs:
                if analyzer.detect_suspicious_paths(line):
                    web_alerts_count += 1
                    parts = line.split('"')
                    request = parts[1] if len(parts) > 1 else line.strip()
                    fields = line.split()
                    ip = fields[0] if fields else "UNKNOWN"
                    print(f" [ALERT] {ip}: подозрительный запрос '{request}'")
            print(f" - Подозрительных веб-запросов: {web_alerts_count}")
        except PermissionError:
            print(f"[!] Нет прав на чтение {nginx_log_path}. Веб-анализ пропущен.")
    else:
        print(" - Веб-анализ пропущен: access.log не найден.")
    print("-" * 60)

    print("[4] Оценка риска")
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)
    print(f" - УРОВЕНЬ РИСКА VPS: {risk}")
    print("-" * 60)

    print("[5] Контроль целостности файла")
    config_path = "vps_secure_config.conf"
    with open(config_path, "w", encoding="utf-8") as file:
        file.write("PermitRootLogin no\nPasswordAuthentication no\n")
    original_hash = analyzer.get_file_hash(config_path)
    print(f" - Исходный SHA-256: {original_hash}")
    with open(config_path, "a", encoding="utf-8") as file:
        file.write("PermitRootLogin yes\n")
    modified_hash = analyzer.get_file_hash(config_path)
    print(f" - Новый SHA-256:    {modified_hash}")
    if original_hash != modified_hash:
        print(" [ALERT] Файл был изменен!")
    else:
        print(" [OK] Изменений нет.")
    print("-" * 60)

    print("[6] Проверка TCP-портов localhost")
    for port in [22, 80, 443, 8080]:
        opened = analyzer.is_port_open("127.0.0.1", port)
        status = "ОТКРЫТ" if opened else "ЗАКРЫТ"
        print(f" * Порт {port}: {status}")
    print("-" * 60)

    if os.path.exists(config_path):
        os.remove(config_path)
    print("АНАЛИЗ ЗАВЕРШЕН")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()
