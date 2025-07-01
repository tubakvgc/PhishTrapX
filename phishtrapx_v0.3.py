import mailparser
import requests
import re

# === VirusTotal API ayarları ===
VT_API_KEY = ""
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# === VirusTotal Sorgusu ===
def vt_lookup(target, is_ip=False):
    url = VT_IP_URL + target if is_ip else VT_DOMAIN_URL + target
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        return f"🔎 VirusTotal ({target}) → Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"
    elif response.status_code == 404:
        return f"ℹ️ VirusTotal: {target} için kayıt bulunamadı."
    else:
        return f"⚠️ VirusTotal API hatası ({target}): HTTP {response.status_code}"

# === Header'dan IP ve domain çekme ===
def extract_ips(text):
    return re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)

def extract_domains(headers):
    domains = set()
    fields = ["From", "Reply-To", "Return-Path"]
    for field in fields:
        val = headers.get(field)
        if val and "@" in val:
            domain = val.split("@")[-1].strip(">").strip()
            domains.add(domain)
    return list(domains)

# === SPF/DKIM/DMARC Açıklayıcı ===
def explain_authentication(spf, auth):
    explanation = ""

    if spf:
        explanation += f"🔎 SPF Sonucu: {spf.strip()}\n"
        if "fail" in spf.lower():
            explanation += "⚠️ SPF FAIL – IP gönderen domain için yetkili değil. Spoofing olabilir.\n"
        elif "softfail" in spf.lower():
            explanation += "⚠️ SPF SOFTFAIL – IP tanınmıyor. Güvenilir değil ama açıkça reddedilmiyor.\n"
        elif "pass" in spf.lower():
            explanation += "✅ SPF PASS – IP yetkili.\n"

    if auth:
        auth = auth.lower()
        explanation += f"\n🔐 Authentication-Results: {auth.strip()}\n"
        if "dkim=fail" in auth:
            explanation += "⚠️ DKIM FAIL – Mail imzalanmış ama doğrulanamamış. İçerik değişmiş olabilir.\n"
        elif "dkim=none" in auth:
            explanation += "⚠️ DKIM NONE – Mail imzasız. Güvensiz.\n"
        elif "dkim=pass" in auth:
            explanation += "✅ DKIM PASS – İmza geçerli.\n"

        if "dmarc=fail" in auth:
            explanation += "⚠️ DMARC FAIL – SPF ve DKIM başarısız. Domain politikası bu durumda maili güvensiz sayar.\n"
        elif "dmarc=pass" in auth:
            explanation += "✅ DMARC PASS – En az biri geçerli. Güvenilir görünüyor.\n"

    return explanation if explanation else "❌ SPF/DKIM/DMARC sonucu bulunamadı."

# === SOC Raporu Üretici ===
def generate_soc_report(subject, from_addr, reply_to, return_path, spf_result, auth_result, vt_notes):
    report = f"""
Merhaba,

Öncelikle dikkatiniz ve geri bildiriminiz için teşekkür ederiz.

**"{subject}"** başlıklı e-posta tarafımızca teknik olarak incelenmiştir.

Yapılan analiz sonucunda; iletide kullanılan kimlik doğrulama protokollerine (SPF, DKIM ve DMARC) ait kayıtların {"uyumsuzluk içerdiği" if "fail" in auth_result.lower() or "softfail" in spf_result.lower() else "uyumlu olduğu"} tespit edilmiştir. Özellikle:

"""
    if "softfail" in spf_result.lower():
        report += "- SPF kaydı **\"SoftFail\"** sonucu vermiştir. Bu, e-postanın gönderildiği IP adresinin, ilgili domain tarafından tanımlı yetkili bir kaynak olmadığını ancak tamamen reddedilmediğini gösterir. Olası spoofing riski barındırır.\n"
    elif "fail" in spf_result.lower():
        report += "- SPF kaydı **\"Fail\"** sonucu vermiştir. Bu, IP adresinin yetkisiz olduğunu ve spoofing ihtimalini güçlendirdiğini gösterir.\n"
    elif "pass" in spf_result.lower():
        report += "- SPF doğrulaması **başarılı (Pass)** olmuştur.\n"

    if "dkim=fail" in auth_result.lower():
        report += "- DKIM doğrulaması **başarısız (Fail)** olmuştur. Mail imzalanmış ancak doğrulanamamıştır. İçerik değişmiş olabilir.\n"
    elif "dkim=none" in auth_result.lower():
        report += "- DKIM imzası **bulunmamaktadır (None)**. Mail doğrulanmamıştır.\n"
    elif "dkim=pass" in auth_result.lower():
        report += "- DKIM doğrulaması **başarılıdır (Pass)**.\n"

    if "dmarc=fail" in auth_result.lower():
        report += "- DMARC politikası **başarısız (Fail)** olarak sonuçlanmıştır. SPF ve DKIM geçerli olmadığı için e-posta karantinaya alınabilir.\n"
    elif "dmarc=pass" in auth_result.lower():
        report += "- DMARC politikası **başarılıdır (Pass)**. SPF veya DKIM geçmiştir.\n"

    report += f"""
E-postada görünen gönderen adresi: {from_addr}
Return-Path alanı: {return_path}
"""

    if reply_to and reply_to != from_addr:
        report += f"""
E-posta içerisinde ayrıca "Reply-To" alanı olarak **{reply_to}** adresi kullanılmıştır.
Bu farklılık, kimlik sahtekarlığı (spoofing) veya dolandırıcılık amaçlı yönlendirme şüphesi oluşturabilir.
"""
    else:
        report += "\nE-posta içerisinde ayrı bir Reply-To adresi bulunmamaktadır.\n"

    report += f"""
Tehdit istihbarat kaynakları kullanılarak yapılan analizlerde, aşağıdaki IP adresleri ve alan adları sorgulanmıştır:
"""
    for item in vt_notes:
        report += f"• {item}\n"

    if reply_to and "@" in reply_to:
        report += f"""

Sonuç olarak, doğrudan kötü amaçlı bir aktivite tespit edilmemekle birlikte; kimlik doğrulama uyumsuzlukları ve genel yapı itibarıyla bu e-postaya karşı dikkatli olunması önerilir.

Gerekli görülmesi halinde aşağıdaki e-posta adresinin kara listeye alınması ve kullanıcıların bilgilendirilmesi uygun olacaktır:

• {reply_to}

Bilgilerinize sunarız.
"""
    else:
        report += f"""
Sonuç olarak, bu e-postada doğrudan kötü niyetli bir aktiviteye dair belirgin bir bulguya rastlanmamıştır. Ancak kimlik doğrulama kontrollerindeki zayıflık nedeniyle benzer iletilere karşı dikkatli olunması tavsiye edilmektedir.

Bilgilerinize sunarız.
"""

    return report

# === Ana İşlem ===
def analyze_eml(file_path):
    mail = mailparser.parse_from_file(file_path)
    headers = mail.headers

    print("\n📥 PHISHTRAPX v0.3 ANALİZ RAPORU\n" + "-"*60)
    print(f"📬 From: {headers.get('From')}")
    print(f"📤 To: {headers.get('To')}")
    print(f"📝 Subject: {headers.get('Subject')}")
    print(f"📆 Date: {headers.get('Date')}")
    print(f"📩 Reply-To: {headers.get('Reply-To')}")
    print(f"📨 Return-Path: {headers.get('Return-Path')}")
    print(f"🧾 Message-ID: {headers.get('Message-ID')}")

    print("\n📡 SPF/DKIM/DMARC ANALİZİ\n" + "-"*60)
    spf_result = headers.get('Received-SPF', '')
    auth_result = headers.get('Authentication-Results', '')
    print(explain_authentication(spf_result, auth_result))

    print("\n🌐 VIRUSTOTAL TI ANALİZİ\n" + "-"*60)
    ips = sorted(set(extract_ips(str(headers))))
    domains = extract_domains(headers)

    vt_results = []
    for ip in ips:
        result = vt_lookup(ip, is_ip=True)
        print(result)
        vt_results.append(result)

    for domain in domains:
        result = vt_lookup(domain, is_ip=False)
        print(result)
        vt_results.append(result)

    print("\n📄 SOC RAPORU\n" + "-"*60)
    soc_report = generate_soc_report(
        subject=headers.get("Subject", "Konu bulunamadı"),
        from_addr=headers.get("From", "Bilinmiyor"),
        reply_to=str(headers.get("Reply-To", "Yok")),
        return_path=headers.get("Return-Path", "Yok"),
        spf_result=spf_result,
        auth_result=auth_result,
        vt_notes=vt_results
    )
    print(soc_report)

    with open("soc_raporu.txt", "w", encoding="utf-8") as f:
        f.write(soc_report)
        print("\n📁 SOC raporu 'soc_raporu.txt' olarak kaydedildi.")

# === Çalıştırıcı ===
if __name__ == "__main__":
    eml_path = input("📁 .eml dosya yolunu girin: ").strip()
    analyze_eml(eml_path)
