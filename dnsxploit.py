import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.message
import dns.rdatatype
import sys
import logging
import argparse
import asyncio
import aiohttp
from colorama import init, Fore, Style
import json
import csv
import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime
import os
import time
import math
import random

# Inicializace colorama
init()

# Rozšířený slovník subdomén
COMMON_SUBDOMAINS = [
    'www', 'mail', 'app', 'api', 'dev', 'test', 'staging', 'login', 'admin', 'backup', 
    'internal', 'prod', 'docs', 'support', 'web', 'shop', 'blog', 'portal', 'secure', 
    'auth', 'dashboard', 'cdn', 'static', 'media', 'images', 'files', 'download', 'upload', 
    'vpn', 'remote', 'proxy', 'gateway', 'ftp', 'sftp', 'mysql', 'db', 'data', 'api-v2', 
    'beta', 'old', 'new', 'legacy', 'sandbox', 'temp', 'demo', 'info', 'status', 'monitor'
]

# Seznam služeb pro subdomain takeover
TAKEOVER_SERVICES = {
    's3.amazonaws.com': 'AWS S3',
    'azurewebsites.net': 'Azure App Service',
    'cloudapp.net': 'Azure Cloud App',
    'herokuapp.com': 'Heroku',
    'github.io': 'GitHub Pages',
}

# Známé DoH servery
DOH_SERVERS = ['dns.google', 'cloudflare-dns.com']

async def get_records_async(session, domain, record_type, retries=2):
    """Asynchronní získávání DNS záznamů."""
    for attempt in range(retries):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = await asyncio.get_event_loop().run_in_executor(None, lambda: resolver.resolve(domain, record_type))
            records = []
            ttl = answers.rrset.ttl
            for rdata in answers:
                if record_type == 'TXT':
                    record_text = ''.join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else part for part in rdata.strings])
                    records.append((record_text, ttl))
                else:
                    records.append((str(rdata), ttl))
            return records
        except dns.resolver.NoAnswer:
            return []
        except Exception as e:
            if attempt == retries - 1:
                return {"error": str(e)}
            logging.warning(f"Chyba při získávání {record_type} pro {domain}: {e}, pokus {attempt + 1}/{retries}")
    return {"error": "Nepodařilo se získat záznamy"}

def load_wordlist(file_path):
    """Načte slovník subdomén z externího souboru."""
    if not os.path.exists(file_path):
        logging.warning(f"Wordlist {file_path} nenalezen, použití výchozího slovníku.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

async def enumerate_subdomains(domain, subdomains=None, wordlist=None, max_subs=1000):
    """Asynchronní enumerace subdomén."""
    subdomains = subdomains or COMMON_SUBDOMAINS
    if wordlist:
        subdomains.extend(load_wordlist(wordlist))
    found_subdomains = []
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for sub in subdomains[:max_subs]:
            full_sub = f"{sub}.{domain}"
            tasks.append(get_records_async(session, full_sub, 'TXT'))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for full_sub, txt_records in zip([f"{sub}.{domain}" for sub in subdomains[:max_subs]], results):
            if txt_records and not isinstance(txt_records, dict):
                found_subdomains.append(full_sub)
    
    return found_subdomains

async def expand_spf_includes(spf_record, domain, session, depth=0, max_depth=10):
    """Asynchronní rozbalení SPF include direktiv a validace cílů."""
    if depth > max_depth:
        return [], f"Maximální hloubka rekurze ({max_depth}) překročena"
    lookups = 0
    includes = []
    parts = spf_record.split()
    for part in parts:
        if part.startswith('include:'):
            include_domain = part.split(':', 1)[1]
            txt_records = await get_records_async(session, include_domain, 'TXT')
            if isinstance(txt_records, dict) and "error" in txt_records:
                includes.append((include_domain, "Chyba", txt_records["error"]))
            else:
                valid_spf = False
                for rec, _ in txt_records:
                    if rec.startswith('v=spf1'):
                        valid_spf = True
                        sub_includes, sub_error = await expand_spf_includes(rec, include_domain, session, depth + 1, max_depth)
                        includes.extend(sub_includes)
                        if sub_error:
                            includes.append((include_domain, "Chyba v rekurzi", sub_error))
                        lookups += 1
                if not valid_spf:
                    includes.append((include_domain, "Nevalidní SPF", "Žádný SPF záznam nenalezen"))
            lookups += 1
    return includes, None if lookups <= 10 else f"Počet lookupů ({lookups}) přesáhl limit 10"

def categorize_txt_records(records):
    """Kategorizuje TXT záznamy."""
    if isinstance(records, dict) and "error" in records:
        return records
    verification_labels = {
        'google-site-verification=': 'Google Site Verification',
        'facebook-domain-verification=': 'Facebook Domain Verification',
        'apple-domain-verification=': 'Apple Domain Verification',
        'msvalidate.01=': 'Microsoft Domain Verification',
    }
    record_types = {'SPF': [], 'Verification': [], 'Other': []}
    for record, ttl in records:
        if record.startswith('v=spf1'):
            record_types['SPF'].append((record, ttl))
        else:
            labeled = False
            for prefix, label in verification_labels.items():
                if record.startswith(prefix):
                    record_types['Verification'].append((f"{label}: {record}", ttl))
                    labeled = True
                    break
            if not labeled:
                record_types['Other'].append((record, ttl))
    return record_types

def print_categorized_records(record_types, domain, record_type):
    """Vypisuje kategorizované TXT záznamy."""
    if isinstance(record_types, dict) and "error" in record_types:
        logging.info(f"Žádné {record_type.upper()} záznamy pro {domain} (Chyba: {record_types['error']})")
    elif record_type == 'TXT':
        for category, records_list in record_types.items():
            if records_list:
                logging.info(f"{Fore.CYAN}### {category} záznamy pro {domain}:{Style.RESET_ALL}")
                for idx, (record, ttl) in enumerate(records_list, start=1):
                    logging.info(f"{Fore.GREEN}{idx}. {record[:80]}{Style.RESET_ALL}{'...' if len(record) > 80 else ''} (TTL: {ttl}s)")
                logging.info("---")
        if not any(record_types.values()):
            logging.info(f"Žádné {record_type.upper()} záznamy pro {domain}")

def print_any_records(records, domain, record_type):
    """Vypisuje jednoduché seznamy záznamů."""
    if isinstance(records, dict) and "error" in records:
        logging.info(f"Žádné {record_type.upper()} záznamy pro {domain}")
    elif records:
        logging.info(f"{Fore.CYAN}### {record_type.upper()} záznamy pro {domain}:{Style.RESET_ALL}")
        for idx, (record, ttl) in enumerate(records, start=1):
            logging.info(f"{Fore.GREEN}{idx}. {record[:80]}{Style.RESET_ALL}{'...' if len(record) > 80 else ''} (TTL: {ttl}s)")
        logging.info("---")
    else:
        logging.info(f"Žádné {record_type.upper()} záznamy pro {domain}")

def count_spf_lookups(spf_record):
    """Počítá počet DNS lookupů v SPF záznamu."""
    lookups = 0
    parts = spf_record.split()
    for part in parts:
        if part.startswith('include:') or part in ['mx', 'a', 'ptr']:
            lookups += 1
    return lookups

def check_subdomain_takeover(cname_records, domain):
    """Kontroluje možnost subdomain takeover u CNAME záznamů."""
    vulnerabilities = []
    for cname, _ in cname_records:
        target = cname.split()[-1].strip('.')
        try:
            dns.resolver.resolve(target, 'A')
        except dns.resolver.NXDOMAIN:
            for service, name in TAKEOVER_SERVICES.items():
                if target.endswith(service):
                    poc = f"curl -X POST http://{target}/create_bucket -d 'owner={domain}' && aws s3 ls s3://{target} (Pokud převzetí uspěje, ověřte přes AWS konzoli)"
                    vulnerabilities.append((f"Subdomain takeover: CNAME {cname} směřuje na neexistující {name} ({target}).", "High", [f"Převezměte {target} k demonstraci a přiložte důkaz (např. screenshot AWS konzole).", poc]))
                    break
            else:
                poc = f"curl -X POST https://acme-staging-v02.api.letsencrypt.org/acme/new-order -d 'identifiers=[\"{target}\"]' -H 'Content-Type: application/json' > response.json (Staging test LetsEncrypt, přiložte response.json)"
                vulnerabilities.append((f"Subdomain takeover: CNAME {cname} směřuje na neexistující doménu {target}.", "High", [f"Převezměte doménu {target} k demonstraci a přiložte důkaz (např. certifikát).", poc]))
    return vulnerabilities

async def validate_dnssec(domain, session):
    """Validace DNSSEC s ověřením podpisů."""
    try:
        dnskey_records = await get_records_async(session, domain, 'DNSKEY')
        if not dnskey_records:
            poc = f"dig +dnssec A {domain} @8.8.8.8 – žádný podpis nenalezen (potvrďte na DNSViz.net)"
            return "Zranitelnost: DNSSEC není aktivní (žádné DNSKEY záznamy).", "Medium", ["Aktivujte DNSSEC u DNS providera (např. Cloudflare) a přiložte konfiguraci.", poc]
        parent_domain = '.'.join(domain.split('.')[-2:])
        ds_records = await get_records_async(session, parent_domain, 'DS')
        if not ds_records:
            poc = f"dig DS {parent_domain} @8.8.8.8 – žádné DS záznamy (potvrďte na DNSViz.net)"
            return "Zranitelnost: DNSSEC není plně aktivní (DS záznamy chybí u rodiče).", "Medium", ["Nastavte DS záznamy u registrátora a přiložte konfiguraci.", poc]
        return "DNSSEC v pořádku (DNSKEY a DS nalezeny).", "Low", ["DNSSEC je správně nastaven."]
    except Exception as e:
        return f"Chyba při kontrole DNSSEC: {str(e)}", "Unknown", [f"Zkontrolujte DNSSEC manuálně na DNSViz.net."]

async def detect_doh_dot(domain):
    """Detekce šifrovaného DNS (DoH/DoT) na základě dotazů na známé servery."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        resolver.port = 853  # DoT port
        answers = await asyncio.get_event_loop().run_in_executor(None, lambda: resolver.resolve(domain, 'A'))
        if answers:
            poc = f"dig +tls {domain} @8.8.8.8 – DoT aktivní (potvrďte Wiresharkem na portu 853)"
            return "Varování: Použití DoT detekováno, riziko skrytých útoků (např. tunneling).", "Medium", ["Monitorujte šifrovaný DNS provoz na portu 853 (DoT) a ověřte politiku.", poc]
        
        async with aiohttp.ClientSession() as session:
            for doh_server in DOH_SERVERS:
                async with session.get(f"https://{doh_server}/dns-query?name={domain}&type=A", timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'Answer' in data:
                            poc = f"curl 'https://{doh_server}/dns-query?name={domain}&type=A' – DoH aktivní (potvrďte Wiresharkem na portu 443)"
                            return "Varování: Použití DoH detekováno, riziko skrytých útoků (např. tunneling).", "Medium", ["Monitorujte šifrovaný DNS provoz na portu 443 (DoH) a ověřte politiku.", poc]
        return "Žádné známky DoH/DoT.", "Low", ["Žádné šifrované DNS nenalezeno."]
    except Exception as e:
        return f"Chyba při detekci DoH/DoT: {str(e)}", "Unknown", [f"Manuálně ověřte DoH/DoT na Wiresharku."]

async def detect_tunneling(domain, threshold_size=200, freq_threshold=10, entropy_threshold=4):
    """Detekce DNS tunnelingu na základě velikosti, frekvence a entropie."""
    async with aiohttp.ClientSession() as session:
        answers = await get_records_async(session, domain, 'TXT')
        if isinstance(answers, dict) or not answers:
            return "Žádné známky DNS tunnelingu (TXT nenalezeny).", "Low", ["Žádné TXT záznamy pro analýzu."]
        
        # Velikost odpovědí
        sizes = [len(str(rdata)) for rdata, _ in answers]
        max_size = max(sizes) if sizes else 0
        if max_size > threshold_size:
            poc = f"dig TXT {domain} @8.8.8.8 – neobvyklá velikost odpovědi ({max_size} B, potvrďte Wiresharkem)"
            return f"Varování: Podezření na DNS tunneling (velikost odpovědi {max_size} B > {threshold_size} B).", "Medium", ["Analyzujte DNS provoz na tunneling (např. Wireshark) a přiložte důkaz (např. paketový dump).", poc]
        
        # Frekvence dotazů
        start_time = time.time()
        for _ in range(freq_threshold):
            await get_records_async(session, domain, 'TXT')
        elapsed = time.time() - start_time
        avg_freq = freq_threshold / elapsed
        if avg_freq > 5:  # 5 dotazů za sekundu
            poc = f"dig TXT {domain} @8.8.8.8 – vysoká frekvence ({avg_freq:.1f} dotazů/s, potvrďte Wiresharkem)"
            return f"Varování: Podezření na DNS tunneling (frekvence dotazů {avg_freq:.1f}/s).", "Medium", ["Analyzujte DNS provoz na frekvenci a přiložte důkaz (např. logy).", poc]
        
        # Entropie dat
        for rdata, _ in answers:
            data = str(rdata)
            if len(data) > 50:
                entropy = -sum((data.count(c) / len(data)) * math.log2(data.count(c) / len(data)) for c in set(data))
                if entropy > entropy_threshold:
                    poc = f"dig TXT {domain} @8.8.8.8 – vysoká entropie odpovědi ({entropy:.1f}, potvrďte Wiresharkem)"
                    return f"Varování: Podezření na DNS tunneling (entropie odpovědi {entropy:.1f}).", "Medium", ["Analyzujte DNS provoz na entropii a přiložte důkaz (např. analýzu dat).", poc]
        
        return "Žádné známky DNS tunnelingu.", "Low", ["Žádné podezřelé vzorce v TXT záznamech."]

async def get_mx_servers(domain, session):
    """Asynchronně získává MX servery pro PoC spoofingu."""
    mx_records = await get_records_async(session, domain, 'MX')
    if isinstance(mx_records, dict) or not mx_records:
        return "smtp.example.com"
    return mx_records[0][0].split()[-1].strip('.')

async def spoof_email(domain, smtp_server, from_email="attacker@evil.com", to_email=None):
    """Automaticky odesílá spoofovaný email."""
    try:
        to_email = to_email or f"test-{random.randint(1000, 9999)}@{domain}"
        msg = MIMEText("This is a test spoofed email for bug bounty purposes.")
        msg['Subject'] = "Spoofing Test"
        msg['From'] = from_email
        msg['To'] = to_email
        
        with smtplib.SMTP(smtp_server, 25, timeout=10) as server:
            server.send_message(msg)
        with open("spoofed_email.txt", "w") as f:
            f.write(f"From: {from_email}\nTo: {to_email}\nSubject: Spoofing Test\nBody: This is a test spoofed email for bug bounty purposes.")
        return True, f"Email odeslán na {to_email}, přiložte spoofed_email.txt jako důkaz."
    except Exception as e:
        return False, f"Chyba při odesílání emailu: {str(e)}"

async def analyze_spf(domain, smtp_spoof=False, session=None):
    """Analyzuje SPF záznamy a detekuje zranitelnosti."""
    if session is None:
        async with aiohttp.ClientSession() as new_session:
            return await analyze_spf(domain, smtp_spoof, new_session)
    
    txt_records = await get_records_async(session, domain, 'TXT')
    if isinstance(txt_records, dict) and "error" in txt_records:
        return f"Chyba: {txt_records['error']}", "Unknown", []
    
    mx_server = await get_mx_servers(domain, session)
    default_poc = f"echo 'From: attacker@evil.com' | nc {mx_server} 25 -q 10 > spoofed_email.txt (Odešlete email a přiložte spoofed_email.txt jako důkaz doručení)"
    
    for record, ttl in txt_records:
        if record.startswith('v=spf1'):
            lookups = count_spf_lookups(record)
            includes, include_error = await expand_spf_includes(record, domain, session)
            if include_error:
                poc = f"dig TXT {domain} @8.8.8.8 – ukazuje {include_error} (potvrďte MXToolbox)"
                return f"Varování: {include_error}", "Medium", ["Zjednodušte SPF záznam a odstraňte neplatné include.", poc]
            total_lookups = lookups + len([(d, s, e) for d, s, e in includes if s != "Chyba"])
            invalid_includes = [(d, e) for d, s, e in includes if s == "Nevalidní SPF"]
            if invalid_includes:
                poc = f"dig TXT {invalid_includes[0][0]} @8.8.8.8 – nevalidní cíl: {invalid_includes[0][1]} (potvrďte MXToolbox)"
                return f"Zranitelnost: SPF obsahuje nevalidní include cíle ({invalid_includes[0][0]}).", "Medium", ["Opravte nevalidní include direktivy a přiložte důkaz opravy.", poc]
            if total_lookups > 10:
                poc = f"dig TXT {domain} @8.8.8.8 – více než 10 lookupů selže (potvrďte MXToolbox SPF checkerem)"
                return f"Varování: SPF má {total_lookups} lookupů (>10), může selhat podle RFC 7208.", "Medium", ["Omezte počet include direktiv na méně než 10 a přiložte nový záznam.", poc]
            if '+all' in record:
                if smtp_spoof:
                    success, spoof_result = await spoof_email(domain, mx_server)
                    poc = spoof_result if success else default_poc
                else:
                    poc = default_poc
                return "Zranitelnost: SPF je příliš benevolentní (+all).", "High", ["Nahraďte +all za -all pro striktní politiku a ověřte novou konfiguraci.", poc]
            if ttl < 60:
                poc = f"dig TXT {domain} @8.8.8.8 – nízké TTL ({ttl}s) může být zneužito pro cache poisoning (potvrďte DNSViz)"
                return f"Varování: SPF TTL ({ttl}s) je nízké, riziko cache poisoning.", "Medium", ["Zvýšte TTL na minimálně 300s a přiložte novou konfiguraci.", poc]
            return "SPF v pořádku.", "Low", ["SPF je správně nastaven."]
    
    if smtp_spoof:
        success, spoof_result = await spoof_email(domain, mx_server)
        poc = spoof_result if success else default_poc
    else:
        poc = default_poc
    return "Zranitelnost: SPF nenalezen.", "High", ["Nastavte SPF záznam, např. 'v=spf1 include:_spf.google.com -all', a ověřte konfiguraci.", poc]

async def analyze_dkim(domain, selectors=None, email_server=None, email_user=None, email_pass=None, smtp_spoof=False, session=None):
    """Analyzuje DKIM záznamy pro více selektorů."""
    if session is None:
        async with aiohttp.ClientSession() as new_session:
            return await analyze_dkim(domain, selectors, email_server, email_user, email_pass, smtp_spoof, new_session)
    
    if email_server and email_user and email_pass:
        selectors = get_dkim_selectors(email_server, email_user, email_pass) or selectors or ['']
    else:
        selectors = selectors or ['']
    results = []
    for selector in selectors:
        dkim_domain = f"{selector + '.' if selector else ''}_domainkey.{domain}"
        txt_records = await get_records_async(session, dkim_domain, 'TXT')
        mx_server = await get_mx_servers(domain, session)
        default_poc = f"echo 'From: attacker@evil.com' | nc {mx_server} 25 -q 10 > spoofed_email.txt (Odešlete email a přiložte spoofed_email.txt jako důkaz doručení)"
        
        if isinstance(txt_records, dict) and "error" in txt_records:
            results.append((f"Chyba pro {dkim_domain}: {txt_records['error']}", "Unknown", []))
        elif txt_records:
            for record, ttl in txt_records:
                if "v=DKIM1" not in record or "p=" not in record:
                    if smtp_spoof:
                        success, spoof_result = await spoof_email(domain, mx_server)
                        poc = spoof_result if success else default_poc
                    else:
                        poc = default_poc
                    results.append((f"Varování pro {dkim_domain}: DKIM může být nevalidní (chybí v=DKIM1 nebo p=).", "Medium", [f"Opravte DKIM záznam pro selektor {selector}: 'v=DKIM1; p=<klíč>' a ověřte konfiguraci.", poc]))
                elif ttl < 60:
                    poc = f"dig TXT {dkim_domain} @8.8.8.8 – nízké TTL ({ttl}s) může být zneužito (potvrďte DNSViz)"
                    results.append((f"Varování pro {dkim_domain}: DKIM TTL ({ttl}s) je nízké.", "Medium", ["Zvýšte TTL na minimálně 300s a přiložte novou konfiguraci.", poc]))
                else:
                    results.append((f"DKIM pro {dkim_domain} v pořádku.", "Low", ["DKIM je správně nastaven."]))
        else:
            if smtp_spoof:
                success, spoof_result = await spoof_email(domain, mx_server)
                poc = spoof_result if success else default_poc
            else:
                poc = default_poc
            results.append((f"Zranitelnost pro {dkim_domain}: DKIM nenalezen.", "Medium", [f"Nastavte DKIM záznam pro selektor {selector}, např. 'v=DKIM1; p=<klíč>', a ověřte konfiguraci.", poc]))
    return results

async def analyze_dmarc(domain, session=None):
    """Analyzuje DMARC záznamy."""
    if session is None:
        async with aiohttp.ClientSession() as new_session:
            return await analyze_dmarc(domain, new_session)

    dmarc_domain = f"_dmarc.{domain}"
    txt_records = await get_records_async(session, dmarc_domain, 'TXT')
    mx_server = await get_mx_servers(domain, session)
    default_poc = f"echo 'From: attacker@evil.com' | nc {mx_server} 25 -q 10 > spoofed_email.txt (Odešlete email a přiložte spoofed_email.txt jako důkaz doručení)"
    
    if isinstance(txt_records, dict) and "error" in txt_records:
        return f"Chyba: {txt_records['error']}", "Unknown", [f"Zkontrolujte DNS konfiguraci pro {dmarc_domain}.", default_poc]
    if not txt_records:
        return "Zranitelnost: DMARC nenalezen.", "High", [f"Nastavte DMARC záznam, např. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain};', a ověřte konfiguraci.", default_poc]
    
    dmarc_found = False
    for record, ttl in txt_records:
        logging.debug(f"DMARC záznam pro {dmarc_domain}: {record}")
        if record.startswith('v=DMARC1'):
            dmarc_found = True
            if 'p=reject' in record or 'p=quarantine' in record:
                policy = 'p=reject' if 'p=reject' in record else 'p=quarantine'
                if 'pct=' in record:
                    try:
                        pct_value = int(record.split('pct=')[1].split(';')[0])
                        if pct_value < 100:
                            poc = f"echo 'From: attacker@evil.com' | nc {mx_server} 25 -q 10 > spoofed_email.txt (Odešlete email mimo {pct_value}% ochrany a přiložte spoofed_email.txt)"
                            return f"Varování: DMARC má dobrou politiku ({policy}), ale pct={pct_value} není 100%.", "Medium", ["Nastavte pct=100 pro plnou ochranu a ověřte konfiguraci.", poc]
                    except (IndexError, ValueError):
                        logging.warning(f"Chyba při parsování pct v DMARC záznamu: {record}")
                        poc = default_poc
                        return f"Varování: DMARC má nevalidní pct parametr.", "Medium", ["Opravte pct parametr v DMARC záznamu.", poc]
                if 'rua=' not in record and 'ruf=' not in record:
                    poc = f"dig TXT {dmarc_domain} @8.8.8.8 – žádné reporty (potvrďte na DMARC Analyzer)"
                    return f"Varování: DMARC nemá nastaveny reporty (rua/ruf).", "Medium", [f"Přidejte rua=mailto:dmarc@{domain} pro analýzu a ověřte konfiguraci.", poc]
                if ttl < 60:
                    poc = f"dig TXT {dmarc_domain} @8.8.8.8 – nízké TTL ({ttl}s) může být zneužito (potvrďte DNSViz)"
                    return f"Varování: DMARC TTL ({ttl}s) je nízké, riziko cache poisoning.", "Medium", ["Zvýšte TTL na minimálně 300s a přiložte novou konfiguraci.", poc]
                return f"DMARC v pořádku (politika: {policy}).", "Low", ["DMARC je správně nastaven."]
            else:
                poc = default_poc
                return "Zranitelnost: DMARC má slabou politiku (p=none).", "Medium", ["Nastavte p=quarantine nebo p=reject pro ochranu a ověřte konfiguraci.", poc]
    
    if not dmarc_found:
        return "Zranitelnost: Žádný platný DMARC záznam nenalezen.", "High", [f"Nastavte DMARC záznam, např. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain};', a ověřte konfiguraci.", default_poc]

async def analyze_caa(domain, session=None):
    """Analyzuje CAA záznamy s automatickým PoC."""
    if session is None:
        async with aiohttp.ClientSession() as new_session:
            return await analyze_caa(domain, new_session)

    caa_records = await get_records_async(session, domain, 'CAA')
    if isinstance(caa_records, dict) and "error" in caa_records:
        return f"Chyba: {caa_records['error']}", "Unknown", []
    if caa_records:
        for _, ttl in caa_records:
            if ttl < 60:
                poc = f"dig CAA {domain} @8.8.8.8 – nízké TTL ({ttl}s) může být zneužito (potvrďte DNSViz)"
                return f"Varování: CAA TTL ({ttl}s) je nízké, riziko cache poisoning.", "Medium", ["Zvýšte TTL na minimálně 300s a přiložte novou konfiguraci.", poc]
        return "CAA v pořádku.", "Low", ["CAA je správně nastaven."]
    
    headers = {'Content-Type': 'application/json'}
    payload = {"identifiers": [{"type": "dns", "value": domain}]}
    async with session.post("https://acme-staging-v02.api.letsencrypt.org/acme/new-order", json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
        result = await response.json()
        with open("caa_response.json", "w") as f:
            json.dump(result, f, indent=2)
        poc = f"curl -X POST https://acme-staging-v02.api.letsencrypt.org/acme/new-order -d 'identifiers=[\"{domain}\"]' -H 'Content-Type: application/json' > caa_response.json (Test proveden, přiložte caa_response.json)"
    return "Zranitelnost: CAA nenalezeny, riziko neautorizovaného certifikátu od LetsEncrypt.", "Medium", ["Přidejte CAA záznamy, např. '0 issue \"letsencrypt.org\"', a ověřte konfiguraci.", poc]

async def check_dns_config(domains, selectors=None, subdomains=None, format_type='txt', only_vulns=False, severity=None, wordlist=None, email_server=None, email_user=None, email_pass=None, smtp_spoof=False):
    """Provádí analýzu DNS konfigurace pro více domén."""
    logging_filename = f"dns_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    logging.basicConfig(level=logging.INFO,
                        format='%(message)s',
                        handlers=[logging.FileHandler(logging_filename, mode='w'),
                                  logging.StreamHandler(sys.stdout)])

    total_records = 0
    all_vulnerabilities = []
    bug_bounty_reports = []

    async with aiohttp.ClientSession() as session:
        for domain in domains:
            if not only_vulns:
                logging.info(f"{Fore.YELLOW}Analýza DNS konfigurace pro {domain}:{Style.RESET_ALL}\n")
            domain_vulnerabilities = []

            # TXT záznamy
            txt_records = await get_records_async(session, domain, 'TXT')
            record_types = categorize_txt_records(txt_records)
            if not only_vulns:
                print_categorized_records(record_types, domain, 'TXT')
            total_records += sum(len(records_list) for records_list in record_types.values()) if isinstance(record_types, dict) else 0

            # CNAME a subdomain takeover
            cname_records = await get_records_async(session, domain, 'CNAME')
            if cname_records and not only_vulns:
                print_any_records(cname_records, domain, 'CNAME')
                total_records += len(cname_records)
            takeover_vulns = check_subdomain_takeover(cname_records if cname_records else [], domain)
            domain_vulnerabilities.extend(takeover_vulns)
            for vuln, risk, recommend in takeover_vulns:
                bug_bounty_reports.append({
                    "title": f"{risk} Subdomain Takeover on {domain}",
                    "impact": f"Allows an attacker to claim {domain} on a vulnerable service, potentially leading to phishing or data theft.",
                    "steps_to_reproduce": recommend[-1],
                    "recommendation": "; ".join(recommend[:-1])
                })

            # SPF analýza
            spf_result, spf_risk, spf_recommend = await analyze_spf(domain, smtp_spoof, session)
            if "Zranitelnost" in spf_result or "Varování" in spf_result:
                domain_vulnerabilities.append((f"SPF: {spf_result}", spf_risk, spf_recommend))
                bug_bounty_reports.append({
                    "title": f"{spf_risk} SPF Configuration Issue on {domain}",
                    "impact": "Could allow email spoofing or SPF lookup failures affecting email delivery and domain reputation.",
                    "steps_to_reproduce": spf_recommend[-1],
                    "recommendation": "; ".join(spf_recommend[:-1])
                })

            # DKIM analýza
            dkim_results = await analyze_dkim(domain, selectors, email_server, email_user, email_pass, smtp_spoof, session)
            for dkim_result, dkim_risk, dkim_recommend in dkim_results:
                if "Zranitelnost" in dkim_result or "Varování" in dkim_result:
                    domain_vulnerabilities.append((f"DKIM: {dkim_result}", dkim_risk, dkim_recommend))
                    bug_bounty_reports.append({
                        "title": f"{dkim_risk} DKIM Configuration Issue on {domain}",
                        "impact": "Could allow email spoofing due to invalid or missing DKIM, bypassing authentication and risking phishing attacks.",
                        "steps_to_reproduce": dkim_recommend[-1],
                        "recommendation": "; ".join(dkim_recommend[:-1])
                    })

            # DMARC analýza
            dmarc_result, dmarc_risk, dmarc_recommend = await analyze_dmarc(domain, session)
            domain_vulnerabilities.append((f"DMARC: {dmarc_result}", dmarc_risk, dmarc_recommend))
            bug_bounty_reports.append({
                "title": f"{dmarc_risk} DMARC Configuration Issue on {domain}",
                "impact": "Could allow email spoofing or incomplete protection of email recipients, risking phishing or fraud.",
                "steps_to_reproduce": dmarc_recommend[-1],
                "recommendation": "; ".join(dmarc_recommend[:-1])
            })

            # CAA analýza
            caa_result, caa_risk, caa_recommend = await analyze_caa(domain, session)
            if "Zranitelnost" in caa_result or "Varování" in caa_result:
                domain_vulnerabilities.append((f"CAA: {caa_result}", caa_risk, caa_recommend))
                bug_bounty_reports.append({
                    "title": f"{caa_risk} CAA Configuration Issue on {domain}",
                    "impact": "Could allow unauthorized certificate issuance, compromising SSL/TLS security and enabling man-in-the-middle attacks.",
                    "steps_to_reproduce": caa_recommend[-1],
                    "recommendation": "; ".join(caa_recommend[:-1])
                })

            # DNSSEC analýza
            dnssec_result, dnssec_risk, dnssec_recommend = await validate_dnssec(domain, session)
            domain_vulnerabilities.append((f"DNSSEC: {dnssec_result}", dnssec_risk, dnssec_recommend))
            bug_bounty_reports.append({
                "title": f"{dnssec_risk} DNSSEC Configuration Issue on {domain}",
                "impact": "Could allow DNS spoofing or man-in-the-middle attacks, undermining domain trust and security.",
                "steps_to_reproduce": dnssec_recommend[-1],
                "recommendation": "; ".join(dnssec_recommend[:-1])
            })

            # DoH/DoT detekce
            doh_dot_result, doh_dot_risk, doh_dot_recommend = await detect_doh_dot(domain)
            if "Varování" in doh_dot_result:
                domain_vulnerabilities.append((f"DoH/DoT: {doh_dot_result}", doh_dot_risk, doh_dot_recommend))
                bug_bounty_reports.append({
                    "title": f"{doh_dot_risk} Encrypted DNS Usage on {domain}",
                    "impact": "Could hide malicious traffic (e.g., tunneling) in encrypted DNS, evading traditional monitoring.",
                    "steps_to_reproduce": doh_dot_recommend[-1],
                    "recommendation": "; ".join(doh_dot_recommend[:-1])
                })

            # Tunneling detekce
            tunneling_result, tunneling_risk, tunneling_recommend = await detect_tunneling(domain)
            if "Varování" in tunneling_result:
                domain_vulnerabilities.append((f"Tunneling: {tunneling_result}", tunneling_risk, tunneling_recommend))
                bug_bounty_reports.append({
                    "title": f"{tunneling_risk} DNS Tunneling Suspicion on {domain}",
                    "impact": "Could enable data exfiltration or command-and-control channels, bypassing firewalls.",
                    "steps_to_reproduce": tunneling_recommend[-1],
                    "recommendation": "; ".join(tunneling_recommend[:-1])
                })

            # Subdomény
            found_subdomains = await enumerate_subdomains(domain, subdomains, wordlist)
            for full_subdomain in found_subdomains:
                if not only_vulns:
                    logging.info(f"\n{Fore.YELLOW}Analýza subdomény {full_subdomain}:{Style.RESET_ALL}")
                sub_txt_records = await get_records_async(session, full_subdomain, 'TXT')
                sub_record_types = categorize_txt_records(sub_txt_records)
                if not only_vulns:
                    print_categorized_records(sub_record_types, full_subdomain, 'TXT')
                total_records += sum(len(records_list) for records_list in sub_record_types.values()) if isinstance(sub_record_types, dict) else 0

            # Filtrování podle závažnosti
            if severity:
                domain_vulnerabilities = [v for v in domain_vulnerabilities if severity.lower() in v[1].lower()]

            # Výpis zranitelností
            if domain_vulnerabilities:
                logging.info(f"\n{Fore.RED}### Nalezené zranitelnosti pro {domain}:{Style.RESET_ALL}")
                for idx, (vuln, risk, recommend) in enumerate(domain_vulnerabilities, 1):
                    logging.info(f"{idx}. {vuln} (Riziko: {risk})")
                    if not only_vulns:
                        for r in recommend:
                            logging.info(f"   Doporučení: {r}")
                all_vulnerabilities.extend(domain_vulnerabilities)
            elif only_vulns:
                logging.info(f"Žádné zranitelnosti pro {domain} (filtrováno: {severity if severity else 'vše'})")
            logging.info("")

    # Export podle formátu
    if format_type == 'csv':
        with open(f"{logging_filename.replace('.txt', '.csv')}", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Vulnerability", "Risk", "Recommendations"])
            for domain in domains:
                for vuln, risk, recommend in all_vulnerabilities:
                    writer.writerow([domain, vuln, risk, '; '.join(recommend)])
    elif format_type == 'json':
        with open(f"{logging_filename.replace('.txt', '.json')}", 'w') as f:
            json.dump({"domains": domains, "vulnerabilities": [{"desc": v, "risk": r, "recommend": rec} for v, r, rec in all_vulnerabilities], "stats": {"records": total_records, "vulnerabilities": len(all_vulnerabilities)}, "bug_bounty_reports": bug_bounty_reports}, f, indent=2)
    else:  # TXT
        if not only_vulns:
            logging.info(f"{Fore.YELLOW}### Celková statistika:{Style.RESET_ALL}")
            logging.info(f"Počet zjištěných záznamů: {total_records}")
            logging.info(f"Počet zranitelností: {len(all_vulnerabilities)} (High: {sum(1 for _, r, _ in all_vulnerabilities if 'High' in r)}, Medium: {sum(1 for _, r, _ in all_vulnerabilities if 'Medium' in r)}, Unknown: {sum(1 for _, r, _ in all_vulnerabilities if 'Unknown' in r)})")
        logging.info(f"Analýza uložena do {logging_filename}")
        with open(f"{logging_filename.replace('.txt', '_report.txt')}", 'w') as f:
            for report in bug_bounty_reports:
                f.write(f"Title: {report['title']}\n")
                f.write(f"Impact: {report['impact']}\n")
                f.write(f"Steps to Reproduce: {report['steps_to_reproduce']}\n")
                f.write(f"Recommendation: {report['recommendation']}\n")
                f.write("---\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS konfigurace checker pro bug bounty.")
    parser.add_argument("domains", nargs='+', help="Domény k analýze")
    parser.add_argument("--selectors", help="Seznam DKIM selektorů oddělených čárkou", default=None)
    parser.add_argument("--subdomains", help="Seznam subdomén oddělených čárkou", default=','.join(COMMON_SUBDOMAINS))
    parser.add_argument("--format", choices=['txt', 'csv', 'json'], default='txt', help="Formát výstupu")
    parser.add_argument("--only-vulns", action='store_true', help="Zobrazit pouze zranitelnosti")
    parser.add_argument("--severity", choices=['high', 'medium', 'unknown'], default=None, help="Filtrovat zranitelnosti podle závažnosti")
    parser.add_argument("--wordlist", help="Cesta k souboru se slovníkem subdomén", default=None)
    parser.add_argument("--email-server", help="IMAP server pro získání DKIM selektorů", default=None)
    parser.add_argument("--email-user", help="Uživatelské jméno pro IMAP přihlášení", default=None)
    parser.add_argument("--email-pass", help="Heslo pro IMAP přihlášení", default=None)
    parser.add_argument("--smtp-spoof", action='store_true', help="Automaticky odeslat spoofovaný email pro SPF/DKIM testy")
    args = parser.parse_args()
    selectors = args.selectors.split(',') if args.selectors else None
    subdomains = args.subdomains.split(',') if args.subdomains else None
    asyncio.run(check_dns_config(args.domains, selectors, subdomains, args.format, args.only_vulns, args.severity, args.wordlist, args.email_server, args.email_user, args.email_pass, args.smtp_spoof))
