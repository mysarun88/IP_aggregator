import requests
import re
import socket
import time
import pandas as pd
import os
import sys
import stat
from datetime import datetime
from collections import defaultdict
from ipwhois import IPWhois
from git import Repo, GitCommandError

# --- Configuration ---
STORAGE_FILE = "threat_intel.csv"
RAW_DATA_DIR = "raw_feeds" # Directory for raw daily downloads
DATA_DIR = "data_exports" 

# Expanded Feed List
FEEDS = [
    {"name": "Blocklist.de (RDP)", "url": "https://lists.blocklist.de/lists/rdp.txt"},
    {"name": "GreenSnow", "url": "http://blocklist.greensnow.co/greensnow.txt"},
    {"name": "CINS Army", "url": "http://cinsscore.com/list/ci-badguys.txt"},
    {"name": "IPSum Level 3", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"name": "DigitalSide MISP", "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"},
    {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
    {"name": "ThreatFox", "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/"},
    {"name": "URLHaus", "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
    {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
    {"name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"}
]

HOSTING_KEYWORDS = [
    'CLOUD', 'VPS', 'HOSTING', 'DATACENTER', 'DIGITALOCEAN', 'AMAZON', 'AWS', 
    'GOOGLE', 'MICROSOFT', 'AZURE', 'OVH', 'HETZNER', 'ALIBABA', 'TENCENT', 
    'ORACLE', 'LINODE', 'VULTR', 'LEASEWEB', 'RACKSPACE', 'AKAMAI'
]

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Define CSV Columns
CSV_COLUMNS = [
    'ip_address', 'first_seen', 'last_seen', 'sources', 'asn', 'isp_name', 
    'country', 'city', 'hostname', 'host_type', 'risk_level', 
    'abuse_contact', 'cidr', 'asn_registry', 'updated_date'
]

# --- Helper: Logging ---
def log_msg(msg, callback=None):
    """Sends log to callback if exists, else prints to stdout."""
    if callback:
        callback(msg)
    else:
        print(msg)

# --- Helper: Git Operations ---
def push_single_file_to_github(file_path, commit_message):
    """Commits and pushes a single file to GitHub immediately."""
    try:
        repo = Repo('.')
        
        # Configure Git user (Essential for headless environments)
        with repo.config_writer() as git_config:
            if not git_config.has_option('user', 'email'):
                git_config.set_value('user', 'email', 'automated@threatintel.app')
                git_config.set_value('user', 'name', 'Threat Intel Bot')

        # Add specific file
        repo.index.add([file_path])
        
        # Commit
        try:
            repo.index.commit(commit_message)
        except Exception:
            return "Nothing to commit"

        # Push with Auth
        origin = repo.remotes.origin
        github_token = os.environ.get('GITHUB_TOKEN')
        
        if github_token:
            current_url = origin.url
            # Check if the current URL is HTTPs and insert the token if needed
            if "https://" in current_url and "@" not in current_url:
                # Using 'oauth2' as username prevents "fatal: could not read Username"
                auth_url = current_url.replace("https://", f"https://oauth2:{github_token}@")
                origin.set_url(auth_url)
        
        origin.push()
        return "Success"
    except Exception as e:
        return f"Git Error: {e}"

# --- Storage Management (CSV) ---

def init_storage():
    """Initializes the CSV file if it doesn't exist."""
    if not os.path.exists(STORAGE_FILE):
        print(f"[-] Creating new storage file: {STORAGE_FILE}")
        df = pd.DataFrame(columns=CSV_COLUMNS)
        df.to_csv(STORAGE_FILE, index=False)
        
    # Security: Restrict permissions (Mac/Linux only)
    try:
        os.chmod(STORAGE_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

def get_existing_ips():
    """Returns a set of all IPs currently in the CSV."""
    try:
        if os.path.exists(STORAGE_FILE) and os.path.getsize(STORAGE_FILE) > 0:
            # Read only the ip_address column for speed
            df = pd.read_csv(STORAGE_FILE, usecols=['ip_address'])
            return set(df['ip_address'].tolist())
    except Exception as e:
        print(f"[!] Error reading existing IPs: {e}")
    return set()

def update_ip_sources(ip, new_sources):
    """Updates the 'sources' and 'last_seen' for an existing IP."""
    try:
        df = pd.read_csv(STORAGE_FILE)
        
        # Find the row index
        idx = df.index[df['ip_address'] == ip].tolist()
        if not idx:
            return # IP not found
            
        idx = idx[0]
        
        # Merge sources
        current_sources_str = str(df.at[idx, 'sources'])
        if pd.isna(current_sources_str) or current_sources_str == 'nan':
            current_sources = set()
        else:
            current_sources = set(s.strip() for s in current_sources_str.split(",") if s.strip())
            
        current_sources.update(new_sources)
        
        # Update fields
        df.at[idx, 'sources'] = ", ".join(sorted(current_sources))
        df.at[idx, 'last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save back to CSV
        df.to_csv(STORAGE_FILE, index=False)
        
    except Exception as e:
        print(f"[!] Error updating IP {ip}: {e}")

def insert_new_ip(data, sources):
    """Appends a new IP record to the CSV."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare row data matching CSV_COLUMNS
    row = {
        'ip_address': data['IP'],
        'first_seen': now,
        'last_seen': now,
        'sources': ", ".join(sorted(sources)),
        'asn': data.get('ASN'),
        'isp_name': data.get('ISP_Name'),
        'country': data.get('Country'),
        'city': data.get('City'),
        'hostname': data.get('Hostname'),
        'host_type': data.get('Host_Type'),
        'risk_level': data.get('Risk_Level'),
        'abuse_contact': data.get('Abuse_Contact'),
        'cidr': data.get('CIDR'),
        'asn_registry': data.get('ASN_Registry'),
        'updated_date': data.get('Updated_Date')
    }
    
    # Create a DataFrame for the single row
    new_df = pd.DataFrame([row])
    
    # Append to CSV file
    # header=False because file already has headers
    try:
        new_df.to_csv(STORAGE_FILE, mode='a', header=not os.path.exists(STORAGE_FILE), index=False)
    except Exception as e:
        print(f"[!] Error writing to CSV: {e}")

# --- Parsing & Enrichment ---

def sanitize_filename(name):
    """Sanitizes string to be safe for filenames."""
    return re.sub(r'[^\w\-_\. ]', '_', name)

def get_daily_raw_path():
    """Creates and returns the path for today's raw data."""
    today = datetime.now().strftime('%Y-%m-%d')
    path = os.path.join(RAW_DATA_DIR, today)
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def fetch_feeds(log_callback=None):
    """
    Checks for local raw files for today. 
    If missing, downloads from source and saves to 'raw_feeds/YYYY-MM-DD/'.
    Returns dict: {ip: [source1, source2]}
    """
    log_msg("[-] Checking/Fetching feeds...", log_callback)
    aggregated = defaultdict(set)
    date_path = get_daily_raw_path()
    
    for feed in FEEDS:
        safe_name = sanitize_filename(feed['name'])
        file_path = os.path.join(date_path, f"{safe_name}.txt")
        content = ""
        
        # 1. Try to read from local Git storage first
        if os.path.exists(file_path):
            log_msg(f"    [+] Reading cached: {feed['name']}", log_callback)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                log_msg(f"    [!] Error reading cache {file_path}: {e}", log_callback)
        
        # 2. Download if not found
        else:
            log_msg(f"    [+] Downloading: {feed['name']}...", log_callback)
            try:
                r = requests.get(feed['url'], timeout=15)
                if r.status_code == 200:
                    content = r.text
                    
                    # Save raw data
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    # --- COMMIT & PUSH IMMEDIATELY ---
                    log_msg(f"    [>] Pushing {safe_name} to GitHub...", log_callback)
                    git_res = push_single_file_to_github(
                        file_path, 
                        f"Raw Feed: {feed['name']} ({datetime.now().strftime('%Y-%m-%d')})"
                    )
                    if git_res != "Success":
                        log_msg(f"        [!] Git Warning: {git_res}", log_callback)
                    # ---------------------------------

                else:
                    log_msg(f"    [!] Failed to fetch {feed['name']} (Status {r.status_code})", log_callback)
            except Exception as e:
                log_msg(f"    [!] Failed to fetch {feed['name']}: {e}", log_callback)

        # 3. Parse IPs from content
        if content:
            ips = set(IP_PATTERN.findall(content))
            for ip in ips:
                if not ip.startswith(('127.', '10.', '192.168.')): 
                    aggregated[ip].add(feed['name'])
            
    return aggregated

def enrich_ip(ip):
    """Deep Forensic Analysis (Whois + RDAP + Reverse DNS)."""
    data = {
        'IP': ip, 
        'ASN': 'Unknown', 'ISP_Name': 'Unknown', 'Country': 'XX',
        'City': 'Unknown', 'Hostname': 'Unknown', 'Abuse_Contact': 'Unknown', 
        'Host_Type': 'Unknown', 'CIDR': 'Unknown', 'ASN_Registry': 'Unknown',
        'Updated_Date': 'Unknown', 'Risk_Level': 'Unknown'
    }
    
    # 1. Reverse DNS
    try:
        socket.setdefaulttimeout(2)
        data['Hostname'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # 2. RDAP/Whois
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1, retry_count=1)
        
        data['ASN'] = res.get('asn', 'Unknown')
        data['ISP_Name'] = res.get('asn_description', 'Unknown')
        data['Country'] = res.get('asn_country_code', 'XX')
        data['ASN_Registry'] = res.get('asn_registry', 'Unknown')
        
        network = res.get('network', {})
        data['CIDR'] = network.get('cidr', 'Unknown')
        data['Updated_Date'] = network.get('updated', 'Unknown')
        data['City'] = network.get('city', 'Unknown')

        objects = res.get('objects', {})
        for _, val in objects.items():
            contact = val.get('contact', {})
            if 'abuse' in val.get('roles', []) or 'abuse' in str(contact).lower():
                emails = contact.get('email')
                if emails:
                    data['Abuse_Contact'] = emails[0].get('value')
                    break
                    
    except Exception:
        pass

    # 3. Heuristics
    isp_upper = str(data['ISP_Name']).upper()
    host_upper = str(data['Hostname']).upper()
    
    if any(k in isp_upper or k in host_upper for k in HOSTING_KEYWORDS):
        data['Host_Type'] = 'Cloud/Hosting'
        data['Risk_Level'] = 'High (Cloud)'
    else:
        data['Host_Type'] = 'Residential/ISP'
        data['Risk_Level'] = 'Moderate (Res)'
        
    return data

def process_in_batches(ip_list, batch_size=10, sleep_time=2):
    """Generator that yields batches and sleeps to respect rate limits."""
    total = len(ip_list)
    for i in range(0, total, batch_size):
        batch = ip_list[i:i + batch_size]
        yield batch
        if i + batch_size < total:
            time.sleep(sleep_time)

def run_forensic_analysis(new_ips, aggregated_data, batch_size=10, sleep_time=2, log_callback=None):
    """Runs enrichment and appends to CSV with live status."""
    total_ips = len(new_ips)
    if total_ips == 0:
        log_msg("[-] No new IPs to analyze.", log_callback)
        return

    log_msg(f"[*] Starting forensic analysis for {total_ips} IPs...", log_callback)
    start_time = time.time()
    processed_count = 0

    for batch in process_in_batches(new_ips, batch_size, sleep_time):
        for ip in batch:
            # Calculate ETA
            elapsed_time = time.time() - start_time
            if processed_count > 0:
                avg_time = elapsed_time / processed_count
                remaining = total_ips - processed_count
                eta_seconds = int(avg_time * remaining)
                eta_str = str(datetime.utcfromtimestamp(eta_seconds).strftime('%H:%M:%S'))
            else:
                eta_str = "Calculating..."

            status_msg = (
                f"    -> Analyzing: {ip:<15} | "
                f"Left: {total_ips - processed_count:<5} | "
                f"ETA: {eta_str}   "
            )
            
            if log_callback:
                log_callback(status_msg)
            else:
                sys.stdout.write("\r" + status_msg)
                sys.stdout.flush()

            try:
                enriched = enrich_ip(ip)
                insert_new_ip(enriched, aggregated_data[ip])
            except Exception as e:
                log_msg(f"\n[!] Error processing {ip}: {e}\n", log_callback)

            processed_count += 1
    
    total_time = time.time() - start_time
    log_msg(f"\n[+] Analysis complete. Total run time: {str(datetime.utcfromtimestamp(total_time).strftime('%H:%M:%S'))}", log_callback)

def export_to_github_repo(log_callback=None):
    """Commits the storage CSV to Git."""
    if not os.path.exists(STORAGE_FILE):
        return "No CSV file found."
    
    msg = push_single_file_to_github(
        STORAGE_FILE, 
        f"Daily Threat Intel Update (CSV): {datetime.now().strftime('%Y-%m-%d')}"
    )
    return f"Export Result: {msg}"
