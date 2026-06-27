import json
import requests
from datetime import datetime

# ===================== КОНФИГУРАЦИЯ =====================
API_KEY = "твой_ключ"  # ВСТАВЬ СВОЙ КЛЮЧ VirusTotal СЮДА
THRESHOLD = 3           # Минимальное число неудачных попыток для проверки

# ===================== ФУНКЦИИ =====================

def check_ip_virustotal(ip):
    """Проверяет IP через VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        else:
            return {"error": f"Ошибка API: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def analyze_logs(logs, threshold=THRESHOLD):
    """Анализирует логи и возвращает отчёт"""
    failed_attempts = {}
    
    for line in logs:
        parts = line.split()
        ip = parts[1]
        if "failed" in line:
            if ip in failed_attempts:
                failed_attempts[ip] += 1
            else:
                failed_attempts[ip] = 1

    # Собираем подозрительные IP
    suspicious_ips = []
    for ip, count in failed_attempts.items():
        if count > threshold:
            # Обогащаем данными из VirusTotal
            vt_data = check_ip_virustotal(ip)
            suspicious_ips.append({
                "ip": ip,
                "failed_attempts": count,
                "status": "blocked" if count > 5 else "monitor",
                "virustotal": vt_data
            })

    return {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": len(logs),
        "total_suspicious": len(suspicious_ips),
        "suspicious_ips": suspicious_ips
    }

# ===================== ЗАПУСК =====================

if __name__ == "__main__":
    # Тестовые логи
    logs = [
        "10:00 5.5.5.5 22 failed",
        "10:01 5.5.5.5 22 failed",
        "10:02 5.5.5.5 22 failed",
        "10:03 5.5.5.5 22 failed",
        "10:04 5.5.5.5 22 success",
        "10:05 10.0.0.2 22 failed",
        "10:06 10.0.0.2 22 failed",
        "10:07 10.0.0.2 22 success",
        "10:08 192.168.1.1 443 allowed",
        "10:09 192.168.1.1 443 allowed"
    ]

    report = analyze_logs(logs)
    
    print("📄 ОТЧЁТ В ФОРМАТЕ JSON:")
    print(json.dumps(report, indent=4, ensure_ascii=False))
