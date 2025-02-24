# DNSxploit  
### Špičkový DNS Checker pro Bug Bounty Lovce

![DNSxploit](https://img.shields.io/badge/DNSxploit-v1.0-blue?style=for-the-badge&logo=shield)  
**Rychlý • Přesný • Automatizovaný**  
DNSxploit odhaluje zranitelnosti v DNS konfiguraci – od nevalidního DKIM po DNS tunneling – a generuje PoC přímo pro bug bounty reporty.

---

## Proč DNSxploit?
- 🚀 **Enumerace subdomén**: Najde 35+ subdomén během sekund (např. `internal.kissflow.com`).
- 🛡️ **DNS analýza**: SPF, DKIM, DMARC, CAA, DNSSEC + tunneling.
- 🔧 **PoC na klik**: Automatické spoofing emaily a CAA testy.
- 📊 **Reporty**: TXT, CSV, JSON + šablony připravené k odeslání.

---

## Rychlý start
1. **Nainstaluj závislosti**:
   ```bash
   pip install dnspython colorama requests aiohttp

    Stáhni DNSxploit:
    bash

git clone https://github.com/stlouky/DNSxploit.git
cd DNSxploit
Spusť analýzu:
bash

    python dnsxploit.py kissflow.com

Příklad v akci

Spusťte python dnsxploit.py kissflow.com a uvidíte:
text
### Nalezené zranitelnosti pro kissflow.com:
1. DKIM: Varování pro _domainkey.kissflow.com (Medium)
   Doporučení: Opravte DKIM: 'v=DKIM1; p=<klíč>'.
   PoC: echo 'From: attacker@evil.com' | nc aspmx2.googlemail.com 25 -q 10 > spoofed_email.txt
2. CAA: Zranitelnost: CAA nenalezeny (Medium)
   Doporučení: Přidejte '0 issue "letsencrypt.org"'.
   PoC: Test proveden, viz caa_response.json
3. Tunneling: Podezření na DNS tunneling (frekvence 52.2/s, Medium)
   Doporučení: Analyzujte provoz.
   PoC: dig TXT kissflow.com @8.8.8.8

Počet zranitelností: 5 (Medium: 3)
Klíčové funkce
Funkce	Co dělá?	Výsledek
🌐 Subdomény	Najde skryté subdomény rychle	internal.kissflow.com
📧 SPF Lookupy	Kontroluje limity RFC 7208	"10+ lookupů"
🔑 DKIM Spoofing	Testuje nevalidní DKIM	spoofed_email.txt
🔒 CAA Test	Automatický LetsEncrypt PoC	caa_response.json
⚠️ Tunneling	Detekuje anomálie v provozu	"52.2 dotazů/s"
Pokročilé použití

    IMAP pro DKIM selektory:
    bash

python dnsxploit.py kissflow.com --email-server imap.gmail.com --email-user user --email-pass pass
Custom Wordlist:
bash
python dnsxploit.py kissflow.com --wordlist subdomains-top1mil.txt
Automatický spoofing:
bash
python dnsxploit.py kissflow.com --smtp-spoof
Filtrování zranitelností:
bash

    python dnsxploit.py kissflow.com --only-vulns --severity medium

    Tip: Stáhněte si subdomains-top1mil.txt z SecLists pro hlubší analýzu.

Autoři

    stlouky: Hlavní mozek projektu, tester a vizionář.
    Grok (xAI): Vývojář a technický designér, vytvořený týmem xAI.

Licence

MIT License – viz LICENSE
Přispějte

Našli jste bug? Máte nápad?

➡️ Vytvořte Issue nebo pošlete Pull Request!
