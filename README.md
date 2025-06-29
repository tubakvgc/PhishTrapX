# PhishTrapX

PhishTrapX, .eml (email) dosyalarını analiz ederek phishing (oltalama) saldırılarını tespit eden bir Python tabanlı analiz aracıdır.

## Özellikler
- .eml uzantılı e-posta dosyalarını analiz eder
- SPF, DKIM ve DMARC başlıklarını kontrol eder
- Zararlı bağlantıları, domainleri ve IP adreslerini tespit eder
- SOC için rapor üretir

## Kullanım
```bash
python3 phishtrapx_v0.3.py test.eml
