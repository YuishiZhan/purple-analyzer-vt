# 🟣 Purple Analyzer with VirusTotal Enrichment

**Анализатор логов с автоматической проверкой подозрительных IP через VirusTotal API.**

## 🚀 Возможности
- Парсинг логов формата `время IP порт действие`
- Обнаружение IP с множеством неудачных попыток (брутфорс)
- Автоматическое обогащение через VirusTotal (репутация IP)
- Генерация JSON-отчёта с деталями по каждому подозрительному IP

## 📊 Пример вывода
```json
{
  "report_date": "2026-06-28 16:13:10",
  "total_events": 8,
  "total_suspicious": 1,
  "suspicious_ips": [
    {
      "ip": "5.5.5.5",
      "failed_attempts": 4,
      "status": "monitor",
      "virustotal": {
        "malicious": 0,
        "suspicious": 1,
        "harmless": 55
      }
    }
  ]
}
