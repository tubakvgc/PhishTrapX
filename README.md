# PhishTrapX

PhishTrapX, .eml ve .msg uzantılı dosyaları analiz ederek phishing saldırılarını tespit eden bir Python tabanlı analiz aracıdır.

## Özellikler
- .eml uzantılı e-posta dosyalarını analiz eder
- SPF, DKIM ve DMARC başlıklarını kontrol eder
- Zararlı bağlantıları, domainleri ve IP adreslerini tespit eder
- SOC için rapor üretir

## Kullanım
```bash
python3 phishtrapx_v0.3.py test.eml
python3 phishtrapx_v0.4.py test2.eml
```
![image](https://github.com/user-attachments/assets/1e819081-2793-4cc0-a3c9-46363cf2cd10)


