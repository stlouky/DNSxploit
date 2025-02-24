# DNSxploit  
### Špičkový DNS Checker pro Bug Bounty

![DNSxploit Logo](https://img.shields.io/badge/DNSxploit-v1.0-blue?style=for-the-badge)  
**Rychlý. Přesný. Automatizovaný.**  
DNSxploit je nástroj pro analýzu DNS konfigurace, který odhaluje zranitelnosti jako chybějící CAA, nevalidní DKIM nebo DNS tunneling – ideální pro bug bounty reporty.

---

## Co umí?
- **Enumerace subdomén**: Najde subdomény jako `internal` nebo `api-v2` během sekund (35+ subdomén na `kissflow.com`).
- **Analýza DNS**: Kontroluje SPF, DKIM, DMARC, CAA, DNSSEC a DNS tunneling.
- **PoC na míru**: Automaticky generuje spoofing emaily a CAA testy (např. `caa_response.json`).
- **Export reportů**: TXT, CSV, JSON + bug bounty šablony připravené k odeslání.

---

## Rychlý start
1. **Instalace**:
   ```bash
   pip install dnspython colorama requests aiohttp
   git clone https://github.com/stlouky/DNSxploit.git
   cd DNSxploit

    Spusťte analýzu:
    bash

    python dnsxploit.py kissflow.com
    Pokročilé možnosti:
        S wordlistem: python dnsxploit.py kissflow.com --wordlist subdomains-top1mil.txt
        Se spoofingem: python dnsxploit.py kissflow.com --smtp-spoof

Příklad v akci

Spusťte python dnsxploit.py kissflow.com a dostanete:
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
Funkce	Popis	Výstup
Subdomény	Rychle najde 35+ subdomén	internal.kissflow.com, ...
SPF Lookupy	Kontroluje limity RFC 7208	"10+ lookupů"
DKIM Spoofing	Testuje nevalidní DKIM	spoofed_email.txt
CAA Test	Automatický LetsEncrypt PoC	caa_response.json
DNS Tunneling	Detekuje anomálie (velikost, frekvence)	"52.2 dotazů/s"
Pro pokročilé

    IMAP pro DKIM: --email-server imap.gmail.com --email-user user --email-pass pass
    Custom Wordlist: --wordlist cesta/k/subdomains.txt
    Pouze zranitelnosti: --only-vulns
    Filtrování: --severity medium

Autoři

    stlouky: Hlavní tester a iniciátor projektu (stlouky).
    Grok: Vývojář a designér, vytvořený xAI.

Licence

MIT License – viz LICENSE
Přispějte

Bugy? Nápady? Pull requesty vítány na GitHub Issues!
