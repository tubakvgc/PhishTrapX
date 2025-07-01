import requests
import re
import os

try:
    import mailparser
except ImportError:
    mailparser = None

try:
    import extract_msg
except ImportError:
    extract_msg = None

VT_API_KEY = ""
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def vt_lookup(target, is_ip=False):
    url = VT_IP_URL + target if is_ip else VT_DOMAIN_URL + target
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return f"• 🔎 VirusTotal ({target}) → Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Harmless: {stats.get('harmless', 0)}"
    elif response.status_code == 404:
        return f"• ℹ️ VirusTotal: {target} için kayıt bulunamadı."
    else:
        return f"• ⚠️ VirusTotal API hatası ({target}): HTTP {response.status_code}"

def extract_ips(text):
    return re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', text)

def extract_domains(headers):
    domains = set()
    for field in ["From", "Reply-To", "Return-Path"]:
        val = headers.get(field)
        if val and "@" in str(val):
            if isinstance(val, list):
                for v in val:
                    domain = v[1].split("@")[1]
                    domains.add(domain)
            else:
                domain = val.split("@")[1].strip("<>")
                domains.add(domain)
    return list(domains)

def explain_authentication(spf, auth):
    explanation = ""
    if spf:
        explanation += f"🔎 SPF Sonucu: {spf.strip()}\n"
        if "fail" in spf.lower():
            explanation += "⚠️ SPF FAIL – IP yetkili değil. Spoofing olabilir.\n"
        elif "softfail" in spf.lower():
            explanation += "⚠️ SPF SOFTFAIL – IP tanınmıyor. Güvenilir değil.\n"
        elif "pass" in spf.lower():
            explanation += "✅ SPF PASS – IP yetkili.\n"

    if auth:
        auth = auth.lower()
        explanation += f"\n🔐 Authentication-Results: {auth.strip()}\n"
        if "dkim=fail" in auth:
            explanation += "⚠️ DKIM FAIL – Mail imzalanmış ama doğrulanamamış.\n"
        elif "dkim=none" in auth:
            explanation += "⚠️ DKIM NONE – Mail imzasız.\n"
        elif "dkim=pass" in auth:
            explanation += "✅ DKIM PASS – İmza geçerli.\n"

        if "dmarc=fail" in auth:
            explanation += "⚠️ DMARC FAIL – SPF ve DKIM başarısız.\n"
        elif "dmarc=pass" in auth:
            explanation += "✅ DMARC PASS – SPF veya DKIM geçerli.\n"

    return explanation if explanation else "❌ SPF/DKIM/DMARC sonucu bulunamadı."

def generate_soc_report(subject, from_addr, reply_to, return_path, spf_result, auth_result, vt_notes):
    report = f"""
📄 SOC RAPORU
------------------------------------------------------------

Merhaba,

Öncelikle dikkatiniz ve geri bildiriminiz için teşekkür ederiz.

**\"{subject}\"** başlıklı e-posta tarafımızca teknik olarak incelenmiştir.

Yapılan analiz sonucunda; iletide kullanılan kimlik doğrulama protokollerine (SPF, DKIM ve DMARC) ait kayıtların {"uyumsuzluk içerdiği" if "fail" in auth_result.lower() or "softfail" in spf_result.lower() else "uyumlu olduğu"} tespit edilmiştir. Özellikle:
"""
    if "softfail" in spf_result.lower():
        report += "\n- SPF kaydı **\"SoftFail\"** sonucu vermiştir. Bu, e-postanın gönderildiği IP adresinin, ilgili domain tarafından tanımlı yetkili bir kaynak olmadığını ancak tamamen reddedilmediğini gösterir. Olası spoofing riski barındırır."
    elif "fail" in spf_result.lower():
        report += "\n- SPF kaydı **\"Fail\"** sonucu vermiştir. Bu, IP adresinin yetkisiz olduğunu ve spoofing ihtimalini güçlendirdiğini gösterir."
    elif "pass" in spf_result.lower():
        report += "\n- SPF doğrulaması **başarılı (Pass)** olmuştur."

    if "dkim=fail" in auth_result.lower():
        report += "\n- DKIM doğrulaması **başarısız (Fail)** olmuştur. Mail imzalanmış ancak doğrulanamamıştır. İçerik değişmiş olabilir."
    elif "dkim=none" in auth_result.lower():
        report += "\n- DKIM imzası **bulunmamaktadır (None)**. Mail doğrulanmamıştır."
    elif "dkim=pass" in auth_result.lower():
        report += "\n- DKIM doğrulaması **başarılıdır (Pass)**."

    if "dmarc=fail" in auth_result.lower():
        report += "\n- DMARC politikası **başarısız (Fail)** olarak sonuçlanmıştır. SPF ve DKIM geçerli olmadığı için e-posta karantinaya alınabilir."
    elif "dmarc=pass" in auth_result.lower():
        report += "\n- DMARC politikası **başarılıdır (Pass)**. SPF veya DKIM geçmiştir."

    report += f"""

E-postada görünen gönderen adresi: {from_addr}
Return-Path alanı: {return_path}
"""

    if reply_to and reply_to != from_addr:
        report += f"""

E-posta içerisinde ayrıca \"Reply-To\" alanı olarak **{reply_to}** adresi kullanılmıştır.
Bu farklılık, kimlik sahtekarlığı (spoofing) veya dolandırıcılık amaçlı yönlendirme şüphesi oluşturabilir.
"""
    else:
        report += "\n\nE-posta içerisinde ayrı bir Reply-To adresi bulunmamaktadır."

    report += "\n\nTehdit istihbarat kaynakları kullanılarak yapılan analizlerde, aşağıdaki IP adresleri ve alan adları sorgulanmıştır:\n"
    for note in vt_notes:
        report += f"{note}\n"

    if reply_to and "@" in str(reply_to):
        report += f"""

Sonuç olarak, doğrudan kötü amaçlı bir aktivite tespit edilmemekle birlikte; kimlik doğrulama uyumsuzlukları ve genel yapı itibarıyla bu e-postaya karşı dikkatli olunması önerilir.

Gerekli görülmesi halinde aşağıdaki e-posta adresinin kara listeye alınması ve kullanıcıların bilgilendirilmesi uygun olacaktır:

• {reply_to}
"""
    else:
        report += """

Sonuç olarak, bu e-postada doğrudan kötü niyetli bir aktiviteye dair belirgin bir bulguya rastlanmamıştır. Ancak kimlik doğrulama kontrollerindeki zayıflık nedeniyle benzer iletilere karşı dikkatli olunması tavsiye edilmektedir.
"""

    report += "\n\nBilgilerinize sunarız."
    return report

def extract_field_from_header(header_text, field_name):
    try:
        header_str = str(header_text)
        match = re.search(rf"{field_name}:\s*(.+)", header_str, re.IGNORECASE)
        return match.group(1).strip() if match else ""
    except Exception:
        return ""

def analyze_file(file_path):
    headers = {}

    if file_path.lower().endswith(".eml"):
        if mailparser is None:
            print("mailparser modülü yüklü değil.")
            return
        mail = mailparser.parse_from_file(file_path)
        headers = mail.headers

    elif file_path.lower().endswith(".msg"):
        if extract_msg is None:
            print("extract-msg modülü yüklü değil.")
            return
        msg = extract_msg.Message(file_path)
        header_str = str(msg.header) if msg.header else ""
        headers = {
            "From": msg.sender,
            "To": msg.to,
            "Subject": msg.subject,
            "Date": msg.date,
            "Reply-To": extract_field_from_header(header_str, "Reply-To"),
            "Return-Path": msg.sender,
            "Received-SPF": extract_field_from_header(header_str, "Received-SPF"),
            "Authentication-Results": extract_field_from_header(header_str, "Authentication-Results")
        }
    else:
        print("Desteklenmeyen dosya formatı.")
        return

    print("\n📥 PHISHTRAPX ANALİZ RAPORU\n" + "-" * 60)
    for key in ["From", "To", "Subject", "Date", "Reply-To", "Return-Path"]:
        print(f"{key}: {headers.get(key)}")

    spf_result = headers.get("Received-SPF", "")
    auth_result = headers.get("Authentication-Results", "")

    print("\n📡 SPF/DKIM/DMARC ANALİZİ\n" + "-" * 60)
    print(explain_authentication(spf_result, auth_result))

    print("\n🌐 VIRUSTOTAL TI ANALİZİ\n" + "-" * 60)
    ips = sorted(set(extract_ips(str(headers))))
    domains = extract_domains(headers)

    vt_results = []
    for ip in ips:
        vt_results.append(vt_lookup(ip, is_ip=True))
    for domain in domains:
        vt_results.append(vt_lookup(domain, is_ip=False))

    for result in vt_results:
        print(result)

    report = generate_soc_report(
        subject=headers.get("Subject", "Yok"),
        from_addr=headers.get("From", "Yok"),
        reply_to=headers.get("Reply-To", "Yok"),
        return_path=headers.get("Return-Path", "Yok"),
        spf_result=spf_result,
        auth_result=auth_result,
        vt_notes=vt_results
    )

    print("-" * 60)
    print(report)

    with open("soc_raporu.txt", "w", encoding="utf-8") as f:
        f.write(report)
        print("\n📁 SOC raporu 'soc_raporu.txt' olarak kaydedildi.")

if __name__ == "__main__":
    path = input("📁 .eml veya .msg dosya yolunu girin: ").strip()
    analyze_file(path)
