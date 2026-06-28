import json
import requests
from datetime import datetime

# ===================== КОНФИГУРАЦИЯ =====================
API_KEY = "твой_ключ"  # ВСТАВЬ СВОЙ КЛЮЧ VirusTotal СЮДА
THRESHOLD = 3

# ===================== ФУНКЦИИ =====================

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        else:
            return {"error": f"Ошибка {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def analyze_logs(logs):
    failed_attempts = {}
    for line in logs:
        parts = line.split()
        ip = parts[1]
        if "failed" in line:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    suspicious_ips = []
    for ip, count in failed_attempts.items():
        if count > THRESHOLD:
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
    logs = [
        "10:00 5.5.5.5 22 failed",
        "10:01 5.5.5.5 22 failed",
        "10:02 5.5.5.5 22 failed",
        "10:03 5.5.5.5 22 failed",
        "10:04 5.5.5.5 22 success",
        "10:05 10.0.0.2 22 failed",
        "10:06 10.0.0.2 22 failed",
        "10:07 10.0.0.2 22 success",
    ]
    report = analyze_logs(logs)
    print(json.dumps(report, indent=4, ensure_ascii=False))