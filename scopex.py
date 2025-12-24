#!/usr/bin/env python3
"""
Scopex - Lightweight scope-aware reconnaissance tool
Version: 2.2
Author: URDev
"""

import requests
import json
import argparse
import sys
import re
import threading
import signal
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
import os
import time
from datetime import datetime

HEADERS = {
    'User-Agent': 'Scopex/2.2 (Reconnaissance Tool)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
}

REQUEST_TIMEOUT = 10
MAX_WORKERS = 10
SCAN_INTERRUPTED = False

def signal_handler(sig, frame):
    global SCAN_INTERRUPTED
    SCAN_INTERRUPTED = True
    print(colored("\n\n⚠️  Interrupt signal received. Finishing current tasks...", 'yellow'))

signal.signal(signal.SIGINT, signal_handler)

class ColorPrinter:
    VERBOSE = True
    SHOW_API_ROUTES = False # shows a LOT of routes, like, a TON of them
    
    @classmethod
    def success(cls, message: str):
        if cls.VERBOSE:
            print(colored(f"[+] {message}", 'green'))
    
    @classmethod
    def warning(cls, message: str):
        if cls.VERBOSE:
            print(colored(f"[!] {message}", 'yellow'))
    
    @classmethod
    def error(cls, message: str):
        if cls.VERBOSE:
            print(colored(f"[-] {message}", 'red'))
    
    @classmethod
    def info(cls, message: str):
        if cls.VERBOSE:
            print(colored(f"[*] {message}", 'cyan'))
    
    @classmethod
    def status(cls, message: str):
        if cls.VERBOSE:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(colored(f"[{timestamp}] {message}", 'blue'))
    
    @classmethod
    def critical(cls, message: str):
        print(colored(f"[CRITICAL] {message}", 'red', attrs=['bold']))
    
    @classmethod
    def api_route(cls, message: str):
        if cls.VERBOSE and cls.SHOW_API_ROUTES:
            print(colored(f"[API] {message}", 'magenta'))

class ProgressIndicator:
    def __init__(self, message: str = "Processing", total: int = 0):
        self.message = message
        self.total = total
        self.current = 0
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.running = False
        self.start_time = None
        self.spinner_thread = None
    
    def _spin(self):
        i = 0
        while self.running and not SCAN_INTERRUPTED:
            elapsed = time.time() - self.start_time if self.start_time else 0
            spinner = self.spinner_chars[i % len(self.spinner_chars)]
            
            if self.total > 0:
                percent = (self.current / self.total) * 100 if self.total > 0 else 0
                print(f"\r{colored(spinner, 'cyan')} {self.message} [{self.current}/{self.total}] {percent:.1f}% ({elapsed:.1f}s)", 
                      end='', flush=True)
            else:
                print(f"\r{colored(spinner, 'cyan')} {self.message}... ({elapsed:.1f}s)", end='', flush=True)
            
            time.sleep(0.1)
            i += 1
        
        if not SCAN_INTERRUPTED:
            print("\r" + " " * 100, end='\r', flush=True)
    
    def start(self):
        if not SCAN_INTERRUPTED:
            self.running = True
            self.start_time = time.time()
            self.spinner_thread = threading.Thread(target=self._spin, daemon=True)
            self.spinner_thread.start()
    
    def update(self, current: int = 1):
        self.current = current
    
    def stop(self, success: bool = True):
        self.running = False
        if self.spinner_thread:
            self.spinner_thread.join(timeout=0.5)
        
        if not SCAN_INTERRUPTED and self.start_time:
            elapsed = time.time() - self.start_time
            if success:
                print(f"\r{colored('✓', 'green')} {self.message} completed ({elapsed:.1f}s)")
            else:
                print(f"\r{colored('✗', 'red')} {self.message} failed ({elapsed:.1f}s)")

class ScopeManager:
    def __init__(self, scope_file: Optional[str] = None):
        self.scope_rules: List[str] = []
        self.scope_enabled = False
        
        if scope_file:
            self.load_scope(scope_file)
            self.scope_enabled = True
    
    def load_scope(self, scope_file: str) -> bool:
        possible_paths = [
            os.path.join('scopes', scope_file),
            scope_file,
            os.path.join(os.path.dirname(__file__), 'scopes', scope_file)
        ]
        
        scope_path = None
        for path in possible_paths:
            if os.path.exists(path):
                scope_path = path
                break
        
        if not scope_path:
            ColorPrinter.error(f"Scope file not found: {scope_file}")
            return False
        
        try:
            with open(scope_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.scope_rules.append(line)
            
            ColorPrinter.success(f"Loaded {len(self.scope_rules)} scope rules from {scope_file}")
            return True
        except Exception as e:
            ColorPrinter.error(f"Error loading scope file: {e}")
            return False
    
    def is_in_scope(self, target: str) -> bool:
        if not self.scope_enabled:
            return True
        
        target_domain = urlparse(target).netloc
        
        for rule in self.scope_rules:
            pattern = rule.replace('.', r'\.').replace('*', '.*')
            if re.match(f'^{pattern}$', target_domain):
                return True
        
        return False

class WordPressDetector:
    WP_PATHS = [
        '/wp-admin/', '/wp-content/', '/wp-login.php', '/xmlrpc.php',
        '/wp-includes/', '/wp-comments-post.php', '/wp-links-opml.php',
        '/wp-cron.php', '/wp-trackback.php', '/wp-config.php',
        '/wp-settings.php', '/wp-load.php', '/wp-json/',
        '/wp-json/wp/v2/posts', '/wp-json/wp/v2/users',
        '/wp-content/themes/', '/wp-content/plugins/',
        '/wp-sitemap.xml', '/feed/', '/comments/feed/'
    ]
    
    PLUGIN_PATTERNS = {
        'akismet': [r'akismet'],
        'bbpress': [r'bbpress'],
        'jetpack': [r'jetpack'],
        'woocommerce': [r'woocommerce', r'wc-'],
        'contact-form-7': [r'contact-form-7', r'wpcf7'],
        'elementor': [r'elementor'],
        'wordfence': [r'wordfence'],
        'buddypress': [r'buddypress'],
        'wp-rocket': [r'wp-rocket'],
        'w3-total-cache': [r'w3-total-cache'],
        'wp-super-cache': [r'wp-super-cache'],
    }
    
    CRITICAL_FILES = [
        '/wp-config.php',
        '/.env',
        '/.git/config',
        '/wp-config.php.backup',
        '/wp-config.php.bak',
        '/wp-content/debug.log',
        '/wp-admin/install.php',
        '/wp-admin/setup-config.php',
    ]
    
    COMMON_FILES = [
        '/readme.html',
        '/license.txt',
        '/wp-config-sample.php',
    ]
    
    def __init__(self, base_url: str):
        self.base_url = self._normalize_url(base_url)
        self.detected = False
        self.version = None
        self.plugins = []
        self.exposed_files = []
        self.users = []
        self.routes = []
        self.brute_force_protected = False
        self.scan_start_time = None
        self.scan_end_time = None
        self.html_content = None
        self.total_duration = 0
    
    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        if SCAN_INTERRUPTED:
            return None
        
        try:
            response = requests.get(
                url=url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
            return response
        except:
            return None
    
    def detect(self) -> bool:
        self.scan_start_time = time.time()
        ColorPrinter.status(f"Starting scan for {self.base_url}")
        
        progress = ProgressIndicator("Checking WordPress indicators")
        progress.start()
        
        try:
            indicators_checked = 0
            
            for path in self.WP_PATHS[:6]:
                if SCAN_INTERRUPTED:
                    break
                
                url = urljoin(self.base_url, path)
                response = self._make_request(url)
                
                if response and response.status_code in [200, 403, 401, 302]:
                    self.detected = True
                    
                    if path == '/wp-json/':
                        ColorPrinter.warning("WordPress REST API detected")
                    elif path == '/wp-json/wp/v2/users':
                        ColorPrinter.warning("User enumeration endpoint exposed")
                    
                    indicators_checked += 1
                    
                    if indicators_checked >= 3:
                        break
            
            if not self.detected:
                homepage = self._make_request(self.base_url)
                if homepage and 'wp-content' in homepage.text.lower():
                    self.detected = True
            
            self.total_duration += time.time() - self.scan_start_time
            progress.stop(success=self.detected)
            
            if self.detected:
                ColorPrinter.success(f"WordPress detected on {self.base_url}")
                return True
            else:
                ColorPrinter.error("WordPress not detected")
                return False
                
        except Exception as e:
            progress.stop(success=False)
            ColorPrinter.error(f"Detection error: {e}")
            return False
    
    def get_version(self) -> Optional[str]:
        if SCAN_INTERRUPTED or not self.detected:
            return None
        
        start_time = time.time()
        progress = ProgressIndicator("Extracting WordPress version")
        progress.start()
        
        try:
            response = self._make_request(self.base_url)
            if not response:
                progress.stop(success=False)
                return None
            
            self.html_content = response.text
            
            match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', 
                            self.html_content, re.IGNORECASE)
            if match:
                self.version = match.group(1)
                self.total_duration += time.time() - start_time
                progress.stop(success=True)
                ColorPrinter.success(f"WordPress Version: {self.version}")
                return self.version
            
            readme_response = self._make_request(urljoin(self.base_url, '/readme.html'))
            if readme_response and 'WordPress' in readme_response.text:
                match = re.search(r'Version\s+([\d\.]+(?:-[a-z0-9]+)?)', 
                                readme_response.text, re.IGNORECASE)
                if match:
                    self.version = f"WordPress {match.group(1)}"
                    self.total_duration += time.time() - start_time
                    progress.stop(success=True)
                    ColorPrinter.success(f"WordPress Version: {match.group(1)}")
                    return self.version
            
            self.total_duration += time.time() - start_time
            progress.stop(success=False)
            ColorPrinter.warning("Could not determine WordPress version")
            return None
            
        except Exception as e:
            self.total_duration += time.time() - start_time
            progress.stop(success=False)
            ColorPrinter.error(f"Version detection error: {e}")
            return None
    
    def check_exposed_files(self) -> List[Dict[str, Any]]:
        if SCAN_INTERRUPTED:
            return []
        
        ColorPrinter.info("Checking for exposed sensitive files...")
        self.exposed_files = []
        
        all_files = self.CRITICAL_FILES + self.COMMON_FILES
        start_time = time.time()
        progress = ProgressIndicator("Testing files", total=len(all_files))
        progress.start()
        
        for i, file_path in enumerate(all_files):
            if SCAN_INTERRUPTED:
                break
            
            progress.update(i + 1)
            url = urljoin(self.base_url, file_path)
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                content = response.text.lower()
                
                if any(x in content for x in ['page not found', 'error', 'redirect', '404']):
                    continue
                
                severity = "critical" if file_path in self.CRITICAL_FILES else "medium"
                
                is_confirmed = self._confirm_file_exposure(file_path, response)
                
                file_info = {
                    'path': file_path,
                    'url': url,
                    'severity': severity,
                    'confirmed': is_confirmed
                }
                
                self.exposed_files.append(file_info)
                
                if severity == "critical" and is_confirmed:
                    ColorPrinter.warning(f"Exposed file: {file_path}")
                elif severity == "critical" and not is_confirmed:
                    ColorPrinter.info(f"File detected (likely intentional): {file_path}")
                else:
                    ColorPrinter.info(f"Common file: {file_path}")
        
        self.total_duration += time.time() - start_time
        progress.stop(success=True)
        
        confirmed_critical = sum(1 for f in self.exposed_files if f['severity'] == 'critical' and f['confirmed'])
        if confirmed_critical > 0:
            ColorPrinter.warning(f"Found {confirmed_critical} confirmed critical files")
        elif self.exposed_files:
            ColorPrinter.info(f"Found {len(self.exposed_files)} files (none confirmed critical)")
        else:
            ColorPrinter.success("No exposed sensitive files found")
        
        return self.exposed_files
    
    def _confirm_file_exposure(self, file_path: str, response: requests.Response) -> bool:
        if file_path == '/wp-config.php':
            content = response.text
            if 'DB_NAME' in content and 'DB_PASSWORD' in content:
                return True
            elif 'wp-settings.php' in content or 'WordPress' in content:
                return False
        return True
    
    def scan_plugins(self) -> List[Dict[str, Any]]:
        if SCAN_INTERRUPTED:
            return []
        
        ColorPrinter.info("Scanning for common plugins...")
        self.plugins = []
        start_time = time.time()
        
        detected_direct = []
        detected_api = []
        
        for plugin_name in self.PLUGIN_PATTERNS.keys():
            if SCAN_INTERRUPTED:
                break
            
            url = urljoin(self.base_url, f'/wp-content/plugins/{plugin_name}/')
            response = self._make_request(url)
            
            if response and response.status_code in [200, 403]:
                detected_direct.append(plugin_name)
                ColorPrinter.success(f"Plugin detected: {plugin_name}")
        
        api_response = self._make_request(urljoin(self.base_url, '/wp-json/'))
        if api_response and api_response.status_code == 200:
            try:
                data = api_response.json()
                if 'routes' in data:
                    routes = json.dumps(data['routes'])
                    for plugin_name, patterns in self.PLUGIN_PATTERNS.items():
                        if plugin_name in detected_direct:
                            continue
                        for pattern in patterns:
                            if re.search(pattern, routes, re.IGNORECASE):
                                if plugin_name not in detected_api:
                                    detected_api.append(plugin_name)
                                    ColorPrinter.info(f"Plugin referenced in API: {plugin_name}")
            except:
                pass
        
        for plugin in detected_direct:
            self.plugins.append({'name': plugin, 'confidence': 'high', 'type': 'direct'})
        
        for plugin in detected_api:
            self.plugins.append({'name': plugin, 'confidence': 'medium', 'type': 'api'})
        
        self.total_duration += time.time() - start_time
        
        if self.plugins:
            direct_count = len([p for p in self.plugins if p['type'] == 'direct'])
            ColorPrinter.success(f"Found {direct_count} installed plugins, {len(detected_api)} referenced in API")
        else:
            ColorPrinter.warning("No common plugins detected")
        
        return self.plugins
    
    def check_brute_force_protection(self) -> bool:
        if SCAN_INTERRUPTED:
            return False
        
        ColorPrinter.info("Checking for brute force protection...")
        start_time = time.time()
        
        protection_plugins = ['wordfence', 'limit-login-attempts', 'ithemes-security',
                            'loginizer', 'wp-cerber', 'shield-security', 'all-in-one-wp-security']
        
        for plugin in protection_plugins:
            if SCAN_INTERRUPTED:
                break
            
            url = urljoin(self.base_url, f'/wp-content/plugins/{plugin}/')
            response = self._make_request(url)
            
            if response and response.status_code in [200, 403]:
                self.brute_force_protected = True
                self.total_duration += time.time() - start_time
                ColorPrinter.warning(f"Brute force protection detected: {plugin}")
                return True
        
        self.total_duration += time.time() - start_time
        ColorPrinter.critical("NO brute force protection detected")
        return False
    
    def get_users(self) -> List[Dict[str, Any]]:
        if SCAN_INTERRUPTED:
            return []
        
        ColorPrinter.info("Attempting to enumerate users...")
        self.users = []
        start_time = time.time()
        
        endpoints = [
            '/wp-json/wp/v2/users',
            '/?rest_route=/wp/v2/users',
            '/wp-json/wp/v2/users?per_page=100'
        ]
        
        for endpoint in endpoints:
            if SCAN_INTERRUPTED:
                break
            
            url = urljoin(self.base_url, endpoint)
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                try:
                    users_data = response.json()
                    if isinstance(users_data, list):
                        for user in users_data:
                            user_info = {
                                'id': user.get('id', 'N/A'),
                                'name': user.get('name', 'N/A'),
                                'username': user.get('slug', 'N/A'),
                                'link': user.get('link', 'N/A')
                            }
                            self.users.append(user_info)
                        break
                except:
                    continue
        
        self.total_duration += time.time() - start_time
        
        if self.users:
            ColorPrinter.success(f"Found {len(self.users)} users via API")
        else:
            ColorPrinter.info("Could not enumerate users")
        
        return self.users
    
    def get_routes(self) -> List[str]:
        if SCAN_INTERRUPTED:
            return []
        
        ColorPrinter.info("Checking REST API routes...")
        self.routes = []
        start_time = time.time()
        
        url = urljoin(self.base_url, '/wp-json/')
        response = self._make_request(url)
        
        if not response or response.status_code != 200:
            self.total_duration += time.time() - start_time
            return self.routes
        
        try:
            data = response.json()
            if 'routes' in data:
                routes = list(data['routes'].keys())
                
                interesting_routes = [
                    r for r in routes 
                    if any(x in r for x in ['/users', '/admin', '/config', '/database', '/backup', '/install', '/wp/v2'])
                ]
                
                for route in interesting_routes[:15]:
                    ColorPrinter.api_route(f"{route}")
                    self.routes.append(route)
                
                if len(routes) > 15 and ColorPrinter.SHOW_API_ROUTES:
                    ColorPrinter.info(f"... and {len(routes) - 15} more routes")
                elif len(routes) > 15:
                    ColorPrinter.info(f"Found {len(routes)} API routes (use --verbose to see all)")
        
        except Exception as e:
            ColorPrinter.warning(f"Could not parse API routes: {e}")
        
        self.total_duration += time.time() - start_time
        return self.routes
    
    def check_vulnerabilities(self) -> List[Dict[str, Any]]:
        if not self.version or SCAN_INTERRUPTED:
            return []
        
        ColorPrinter.info(f"Checking vulnerabilities for {self.version}...")
        start_time = time.time()
        
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', self.version)
        if not version_match:
            self.total_duration += time.time() - start_time
            return []
        
        version_num = version_match.group(1)
        vulnerabilities = []
        
        try:
            progress = ProgressIndicator("Querying CVE database")
            progress.start()
            
            cve_url = f"https://cve.circl.lu/api/search/wordpress/{version_num}"
            response = requests.get(cve_url, timeout=REQUEST_TIMEOUT)
            
            progress.stop(success=True)
            
            if response and response.status_code == 200:
                data = response.json()
                if data and 'data' in data:
                    for vuln in data['data'][:5]:
                        vuln_info = {
                            'id': vuln.get('id', 'N/A'),
                            'summary': vuln.get('summary', 'N/A'),
                            'cvss': vuln.get('cvss', 0.0)
                        }
                        vulnerabilities.append(vuln_info)
            
            if vulnerabilities:
                ColorPrinter.critical(f"Found {len(vulnerabilities)} potential vulnerabilities!")
                for vuln in vulnerabilities[:3]:
                    cvss = vuln.get('cvss', 0)
                    if cvss >= 7.0:
                        ColorPrinter.critical(f"{vuln['id']}: CVSS {cvss} - {vuln['summary'][:80]}...")
                    elif cvss >= 4.0:
                        ColorPrinter.warning(f"{vuln['id']}: CVSS {cvss} - {vuln['summary'][:80]}...")
                    else:
                        ColorPrinter.info(f"{vuln['id']}: CVSS {cvss} - {vuln['summary'][:80]}...")
            else:
                ColorPrinter.success("No known vulnerabilities found in CVE database")
        
        except Exception as e:
            ColorPrinter.warning(f"Could not fetch vulnerability data: {e}")
        
        self.total_duration += time.time() - start_time
        return vulnerabilities
    
    def generate_risk_summary(self) -> Dict[str, Any]:
        if not self.detected:
            return {'risk_level': 'unknown', 'score': 0, 'findings': []}
        
        score = 0
        findings = []
        
        confirmed_critical = sum(1 for f in self.exposed_files if f['severity'] == 'critical' and f['confirmed'])
        if confirmed_critical > 0:
            score += min(30, confirmed_critical * 10)
            findings.append(f"Critical files exposed: {confirmed_critical}")
        
        if self.users:
            user_score = min(20, len(self.users) * 4)
            score += user_score
            findings.append(f"Users enumerated: {len(self.users)}")
        
        if not self.brute_force_protected:
            score += 15
            findings.append("No brute force protection")
        
        if self.version and ('alpha' in self.version.lower() or 'beta' in self.version.lower()):
            score += 10
            findings.append("Development version in use")
        
        if score >= 50:
            risk_level = 'CRITICAL'
        elif score >= 35:
            risk_level = 'HIGH'
        elif score >= 20:
            risk_level = 'MEDIUM'
        elif score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'INFO'
        
        return {
            'risk_level': risk_level,
            'score': score,
            'findings': findings
        }
    
    def to_dict(self) -> Dict[str, Any]:
        self.scan_end_time = time.time()
        scan_duration = self.total_duration if self.total_duration > 0 else (
            self.scan_end_time - self.scan_start_time if self.scan_start_time else 0
        )
        
        return {
            'base_url': self.base_url,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_duration': scan_duration,
            'detected': self.detected,
            'version': self.version,
            'plugins': self.plugins,
            'exposed_files': self.exposed_files,
            'users_count': len(self.users),
            'users': self.users,
            'routes_count': len(self.routes),
            'brute_force_protected': self.brute_force_protected,
            'vulnerabilities': self.check_vulnerabilities(),
            'risk_assessment': self.generate_risk_summary()
        }

class OutputManager:
    def __init__(self, json_output: bool = False, silent: bool = False):
        self.json_output = json_output
        self.silent = silent
        self.results = {}
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        os.makedirs('output', exist_ok=True)
    
    def add_result(self, target: str, result: Dict[str, Any]) -> None:
        self.results[target] = result
    
    def get_safe_filename(self, text: str) -> str:
        safe = re.sub(r'^https?://', '', text)
        safe = re.sub(r'[^\w\-\.]', '_', safe)
        return safe[:50]
    
    def print_banner(self):
        if self.silent or SCAN_INTERRUPTED:
            return
        
        banner = r"""
  ______                                           __    __
 /      \                                         /  |  /  |
/$$$$$$  |  _______   ______    ______    ______  $$ |  $$ |
$$ \__$$/  /       | /      \  /      \  /      \ $$  \/$$/
$$      \ /$$$$$$$/ /$$$$$$  |/$$$$$$  |/$$$$$$  | $$  $$<
 $$$$$$  |$$ |      $$ |  $$ |$$ |  $$ |$$    $$ |  $$$$  \
/  \__$$ |$$ \_____ $$ \__$$ |$$ |__$$ |$$$$$$$$/  $$ /$$  |
$$    $$/ $$       |$$    $$/ $$    $$/ $$       |$$ |  $$ |
 $$$$$$/   $$$$$$$/  $$$$$$/  $$$$$$$/   $$$$$$$/ $$/   $$/
                              $$ |
            by URDev          $$ |
            v2.2              $$/
"""
        print(colored(banner, 'cyan'))
        print(colored("🔍 Scopex - Lightweight Scope-Aware Reconnaissance Tool\n", 'yellow'))
    
    def print_scan_summary(self, target: str, scope_manager: ScopeManager):
        if self.silent or SCAN_INTERRUPTED:
            return
        
        print(colored("\n" + "="*60, 'blue'))
        print(colored("SCAN SUMMARY", 'blue', attrs=['bold']))
        print(colored("="*60, 'blue'))
        print(colored(f"Target:        {target}", 'white'))
        print(colored(f"Scope Enabled: {scope_manager.scope_enabled}", 'white'))
        if scope_manager.scope_enabled:
            print(colored(f"Scope Rules:   {len(scope_manager.scope_rules)}", 'white'))
        print(colored(f"Scan ID:       {self.scan_id}", 'white'))
        print(colored("="*60 + "\n", 'blue'))
    
    def print_results(self, wp_detector: WordPressDetector):
        if self.silent or SCAN_INTERRUPTED:
            return
        
        print(colored("\n" + "="*60, 'green'))
        print(colored("WORDPRESS FINDINGS", 'green', attrs=['bold']))
        print(colored("="*60, 'green'))
        
        if wp_detector.detected:
            print(colored(f"✅ WordPress Detected", 'green'))
            
            if wp_detector.version:
                print(colored(f"   Version: {wp_detector.version}", 'cyan'))
            
            if wp_detector.plugins:
                direct_plugins = [p for p in wp_detector.plugins if p.get('type') == 'direct']
                api_plugins = [p for p in wp_detector.plugins if p.get('type') == 'api']
                
                if direct_plugins:
                    print(colored(f"   Installed Plugins ({len(direct_plugins)}):", 'cyan'))
                    for plugin in direct_plugins:
                        print(colored(f"     • {plugin['name']}", 'white'))
                
                if api_plugins:
                    print(colored(f"   Referenced in API ({len(api_plugins)}):", 'cyan'))
                    for plugin in api_plugins[:3]:
                        print(colored(f"     • {plugin['name']}", 'white', attrs=['dark']))
                    if len(api_plugins) > 3:
                        print(colored(f"     • ... and {len(api_plugins) - 3} more", 'white', attrs=['dark']))
            
            confirmed_critical = [f for f in wp_detector.exposed_files if f['severity'] == 'critical' and f['confirmed']]
            if confirmed_critical:
                print(colored(f"   🔴 Critical Files ({len(confirmed_critical)}):", 'red'))
                for file in confirmed_critical:
                    print(colored(f"     • {file['path']}", 'white'))
            
            unconfirmed_critical = [f for f in wp_detector.exposed_files if f['severity'] == 'critical' and not f['confirmed']]
            if unconfirmed_critical:
                print(colored(f"   ⚠️  Detected Files ({len(unconfirmed_critical)}):", 'yellow'))
                for file in unconfirmed_critical[:3]:
                    print(colored(f"     • {file['path']} (likely intentional)", 'white', attrs=['dark']))
            
            if wp_detector.users:
                print(colored(f"   👥 Users ({len(wp_detector.users)}):", 'cyan'))
                for user in wp_detector.users[:3]:
                    print(colored(f"     • {user['name']} ({user['username']})", 'white'))
                if len(wp_detector.users) > 3:
                    print(colored(f"     • ... and {len(wp_detector.users) - 3} more", 'white'))
            
            if wp_detector.brute_force_protected:
                print(colored("   🛡️  Brute Force Protection: YES", 'green'))
            else:
                print(colored("   🔴 Brute Force Protection: NO", 'red'))
            
            risk = wp_detector.generate_risk_summary()
            if risk['findings']:
                print(colored(f"\n   📊 Risk Assessment:", 'magenta'))
                print(colored(f"     • Level: {risk['risk_level']}", 'white'))
                print(colored(f"     • Score: {risk['score']}/100", 'white'))
                for finding in risk['findings']:
                    print(colored(f"     • {finding}", 'white'))
            
            duration = wp_detector.total_duration if wp_detector.total_duration > 0 else 0
            if duration > 0:
                print(colored(f"\n   ⏱️  Total scan duration: {duration:.1f} seconds", 'blue'))
        else:
            print(colored("❌ WordPress Not Detected", 'red'))
        
        print(colored("="*60, 'green'))
    
    def save_results(self, target: str, scope_name: Optional[str] = None):
        if target not in self.results:
            return
        
        result = self.results[target]
        safe_target = self.get_safe_filename(target)
        
        if scope_name:
            safe_scope = self.get_safe_filename(scope_name).replace('.txt', '')
            base_filename = f"{safe_scope}_{safe_target}_{self.scan_id}"
        else:
            base_filename = f"{safe_target}_{self.scan_id}"
        
        txt_path = os.path.join('output', f"{base_filename}.txt")
        with open(txt_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("Scopex Scan Results\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {result.get('base_url', 'N/A')}\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Time: {result.get('scan_timestamp', 'N/A')}\n")
            f.write(f"Duration: {result.get('scan_duration', 0):.1f}s\n")
            
            if result.get('detected'):
                risk = result.get('risk_assessment', {})
                f.write(f"\nRisk Level: {risk.get('risk_level', 'N/A')}\n")
                f.write(f"Risk Score: {risk.get('score', 0)}/100\n")
                
                f.write("\n=== FINDINGS ===\n\n")
                f.write(f"Version: {result.get('version', 'N/A')}\n\n")
                
                if result.get('plugins'):
                    direct = [p for p in result['plugins'] if p.get('type') == 'direct']
                    api_ref = [p for p in result['plugins'] if p.get('type') == 'api']
                    
                    if direct:
                        f.write(f"Installed Plugins ({len(direct)}):\n")
                        for plugin in direct:
                            f.write(f"  • {plugin['name']}\n")
                        f.write("\n")
                    
                    if api_ref:
                        f.write(f"Referenced in API ({len(api_ref)}):\n")
                        for plugin in api_ref:
                            f.write(f"  • {plugin['name']}\n")
                        f.write("\n")
                
                if result.get('exposed_files'):
                    confirmed = [f for f in result['exposed_files'] if f.get('confirmed', False)]
                    if confirmed:
                        f.write(f"Confirmed Exposed Files ({len(confirmed)}):\n")
                        for file in confirmed:
                            f.write(f"  • [{file['severity'].upper()}] {file['path']}\n")
                        f.write("\n")
                
                if result.get('users'):
                    f.write(f"Users ({len(result['users'])}):\n")
                    for user in result['users'][:10]:
                        f.write(f"  • {user['name']} (@{user['username']})\n")
                    f.write("\n")
                
                f.write(f"Brute Force Protection: {result.get('brute_force_protected', False)}\n")
            
            f.write("\n" + "="*60 + "\n")
        
        if self.json_output:
            json_path = os.path.join('output', f"{base_filename}.json")
            with open(json_path, 'w') as f:
                json.dump({
                    'scan_info': {
                        'tool': 'Scopex',
                        'version': '2.2',
                        'target': target,
                        'scan_id': self.scan_id,
                        'timestamp': result.get('scan_timestamp')
                    },
                    'results': result
                }, f, indent=2)
            
            if not self.silent:
                ColorPrinter.success(f"JSON results saved to {json_path}")
        
        if not self.silent:
            ColorPrinter.success(f"Text results saved to {txt_path}")
    
    def save_summary_report(self, scope_name: Optional[str] = None):
        if not self.results:
            return
        
        summary_filename = f"summary_{self.scan_id}"
        if scope_name:
            safe_scope = self.get_safe_filename(scope_name).replace('.txt', '')
            summary_filename = f"{safe_scope}_summary_{self.scan_id}"
        
        txt_path = os.path.join('output', f"{summary_filename}.txt")
        with open(txt_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("Scopex Scan Summary Report\n")
            f.write("="*60 + "\n\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets scanned: {len(self.results)}\n")
            
            if scope_name:
                f.write(f"Scope: {scope_name}\n")
            
            wordpress_count = sum(1 for r in self.results.values() if r.get('detected'))
            f.write(f"\nWordPress Detected: {wordpress_count}/{len(self.results)}\n\n")
            
            high_risk = 0
            for target, result in self.results.items():
                risk = result.get('risk_assessment', {})
                risk_level = risk.get('risk_level', 'INFO')
                if risk_level in ['CRITICAL', 'HIGH']:
                    high_risk += 1
                
                f.write(f"Target: {target}\n")
                f.write(f"  WordPress: {'YES' if result.get('detected') else 'NO'}\n")
                if result.get('detected'):
                    f.write(f"  Version: {result.get('version', 'N/A')}\n")
                    f.write(f"  Risk Level: {risk_level}\n")
                    f.write(f"  Users Found: {result.get('users_count', 0)}\n")
                f.write("\n")
            
            f.write(f"\nHigh/Critical Risk Targets: {high_risk}/{len(self.results)}\n")
            f.write("="*60 + "\n")
        
        if not self.silent:
            ColorPrinter.success(f"Summary report saved to {txt_path}")

def scan_target(target: str, output: OutputManager, scope_manager: ScopeManager, scope_name: Optional[str] = None) -> bool:
    if SCAN_INTERRUPTED:
        return False
    
    try:
        wp_detector = WordPressDetector(target)
        
        if wp_detector.detect():
            wp_detector.get_version()
            wp_detector.check_exposed_files()
            wp_detector.scan_plugins()
            wp_detector.check_brute_force_protection()
            wp_detector.get_users()
            wp_detector.get_routes()
            wp_detector.check_vulnerabilities()
            
            if not output.silent:
                output.print_results(wp_detector)
            
            output.add_result(target, wp_detector.to_dict())
            output.save_results(target, scope_name)
            
            return True
        else:
            output.add_result(target, wp_detector.to_dict())
            output.save_results(target, scope_name)
            return False
            
    except Exception as e:
        ColorPrinter.error(f"Error scanning {target}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Scopex - Lightweight scope-aware reconnaissance tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url example.com
  %(prog)s --url example.com --verbose
  %(prog)s --url example.com --json
  %(prog)s --list targets.txt
  %(prog)s --scope scope.txt
  %(prog)s --url example.com --silent
        """
    )
    
    parser.add_argument('--url', help='Target domain')
    parser.add_argument('--list', help='File with multiple targets')
    parser.add_argument('--scope', help='Scope filename')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--silent', action='store_true', help='No console output')
    
    args = parser.parse_args()
    
    if not args.url and not args.list and not args.scope:
        parser.error('At least one of --url, --list, or --scope must be specified')
    
    ColorPrinter.VERBOSE = not args.silent
    ColorPrinter.SHOW_API_ROUTES = args.verbose
    
    output = OutputManager(json_output=args.json, silent=args.silent)
    
    if not args.silent:
        output.print_banner()
    
    scope_manager = ScopeManager(args.scope)
    
    targets = []
    
    if args.url:
        targets.append(args.url)
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            ColorPrinter.error(f"Target list file not found: {args.list}")
            sys.exit(1)
    
    if not targets and args.scope:
        for rule in scope_manager.scope_rules:
            if not rule.startswith('*'):
                targets.append(f"https://{rule}")
            elif rule.startswith('*.'):
                ColorPrinter.info(f"Wildcard domain in scope: {rule}")
    
    if not targets:
        ColorPrinter.error("No valid targets found to scan")
        sys.exit(1)
    
    ColorPrinter.info(f"Loaded {len(targets)} target(s) for scanning")
    
    successful_scans = 0
    total_targets = len(targets)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        
        for target in targets:
            if SCAN_INTERRUPTED:
                break
            
            if not scope_manager.is_in_scope(target):
                ColorPrinter.warning(f"Target {target} is out of scope - skipping")
                total_targets -= 1
                continue
            
            if not args.silent:
                output.print_scan_summary(target, scope_manager)
            
            future = executor.submit(scan_target, target, output, scope_manager, args.scope)
            futures[future] = target
        
        for future in as_completed(futures):
            if SCAN_INTERRUPTED:
                break
            
            target = futures[future]
            try:
                success = future.result(timeout=REQUEST_TIMEOUT * 10)
                if success:
                    successful_scans += 1
            except Exception as e:
                ColorPrinter.error(f"Scan failed for {target}: {e}")
    
    if successful_scans > 0:
        output.save_summary_report(args.scope)
    
    if not args.silent:
        if SCAN_INTERRUPTED:
            ColorPrinter.warning(f"\nScan interrupted. Completed: {successful_scans}/{total_targets}")
        else:
            print(colored("\n" + "="*60, 'green'))
            print(colored("SCAN COMPLETED", 'green', attrs=['bold']))
            print(colored("="*60, 'green'))
            print(colored(f"✅ Successful: {successful_scans}/{total_targets}", 'green'))
            print(colored("📁 Results saved in 'output/' directory", 'cyan'))
            print(colored("="*60, 'green'))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ColorPrinter.warning("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        ColorPrinter.error(f"Unexpected error: {e}")
        sys.exit(1)
