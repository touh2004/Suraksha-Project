# threat_intel.py — SURAKSHA Threat Intelligence
# Checks IPs against free threat feeds:
#   1. AbuseIPDB  — crowdsourced abuse reports
#   2. GreyNoise  — internet scanner database
#   3. Local cache — avoids hitting rate limits

import requests
import json
import os
from datetime import datetime, timedelta

CACHE_FILE   = 'models/threat_intel_cache.json'
CACHE_HOURS  = 24   # re-check IPs after 24 hours

# ── Free API keys — get these in 2 minutes ────────────────────
# AbuseIPDB: https://www.abuseipdb.com/register (free, 1000/day)
# GreyNoise: https://www.greynoise.io (free community tier)
ABUSEIPDB_KEY = ''   # paste your key here
GREYNOISE_KEY = ''   # paste your key here


class ThreatIntel:
    def __init__(self):
        self.cache = {}
        self._load_cache()

        # Built-in known bad IPs — no API needed
        # These are well-known attack infrastructure IPs
        self.known_bad = {
            '185.220.101.0' : {'source': 'Tor Exit Node',       'risk': 'HIGH'},
            '185.220.101.34': {'source': 'Tor Exit Node',       'risk': 'HIGH'},
            '162.247.74.74' : {'source': 'Tor Exit Node',       'risk': 'HIGH'},
            '198.96.155.3'  : {'source': 'Tor Exit Node',       'risk': 'HIGH'},
            '23.129.64.131' : {'source': 'Known Scanner',       'risk': 'MEDIUM'},
            '80.82.77.139'  : {'source': 'Shodan Scanner',      'risk': 'MEDIUM'},
            '80.82.77.33'   : {'source': 'Shodan Scanner',      'risk': 'MEDIUM'},
            '85.25.43.94'   : {'source': 'Known ICS Scanner',   'risk': 'HIGH'},
            '71.6.135.131'  : {'source': 'Censys Scanner',      'risk': 'MEDIUM'},
        }

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                self.cache = json.load(f)

    def _save_cache(self):
        os.makedirs('models', exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _is_cache_fresh(self, ip):
        if ip not in self.cache:
            return False
        cached_time = datetime.fromisoformat(self.cache[ip]['checked_at'])
        return datetime.now() - cached_time < timedelta(hours=CACHE_HOURS)

    def check_ip(self, ip):
        """
        Full threat intel check on an IP.
        Returns threat profile dict.
        """
        # Skip private IPs
        private = ['192.168.', '10.', '172.', '127.', '0.', '224.']
        if any(ip.startswith(p) for p in private):
            return {
                'ip'         : ip,
                'is_threat'  : False,
                'risk'       : 'NONE',
                'source'     : 'private IP',
                'description': 'Internal network address',
                'confidence' : 0,
            }

        # Check built-in known bad list first (instant, no API)
        if ip in self.known_bad:
            info = self.known_bad[ip]
            return {
                'ip'         : ip,
                'is_threat'  : True,
                'risk'       : info['risk'],
                'source'     : info['source'],
                'description': f"Known malicious IP — {info['source']}",
                'confidence' : 95,
            }

        # Check cache
        if self._is_cache_fresh(ip):
            return self.cache[ip]

        # Try AbuseIPDB if key available
        result = None
        if ABUSEIPDB_KEY:
            result = self._check_abuseipdb(ip)

        # Try GreyNoise if key available
        if not result and GREYNOISE_KEY:
            result = self._check_greynoise(ip)

        # Fallback — basic heuristic check
        if not result:
            result = self._heuristic_check(ip)

        # Cache the result
        result['checked_at'] = datetime.now().isoformat()
        self.cache[ip]       = result
        self._save_cache()
        return result

    def _check_abuseipdb(self, ip):
        """Check AbuseIPDB — free 1000 requests/day."""
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={
                    'Key'   : ABUSEIPDB_KEY,
                    'Accept': 'application/json',
                },
                params={
                    'ipAddress'      : ip,
                    'maxAgeInDays'   : 90,
                    'verbose'        : True,
                },
                timeout=4,
            )
            data = r.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)

            is_threat = score > 25
            risk      = 'CRITICAL' if score > 75 else \
                        'HIGH'     if score > 50 else \
                        'MEDIUM'   if score > 25 else 'LOW'

            return {
                'ip'          : ip,
                'is_threat'   : is_threat,
                'risk'        : risk,
                'source'      : 'AbuseIPDB',
                'abuse_score' : score,
                'reports'     : data.get('totalReports', 0),
                'country'     : data.get('countryCode', ''),
                'isp'         : data.get('isp', ''),
                'description' : f"Abuse score: {score}/100 — {data.get('totalReports',0)} reports",
                'confidence'  : score,
                'is_tor'      : data.get('isTor', False),
            }
        except Exception as e:
            return None

    def _check_greynoise(self, ip):
        """Check GreyNoise — identifies internet scanners."""
        try:
            r = requests.get(
                f'https://api.greynoise.io/v3/community/{ip}',
                headers={'key': GREYNOISE_KEY},
                timeout=4,
            )
            data = r.json()
            noise       = data.get('noise', False)
            riot        = data.get('riot', False)
            classification = data.get('classification', 'unknown')

            is_threat = noise and not riot
            risk      = 'HIGH'   if classification == 'malicious' else \
                        'MEDIUM' if noise and not riot else 'LOW'

            return {
                'ip'            : ip,
                'is_threat'     : is_threat,
                'risk'          : risk,
                'source'        : 'GreyNoise',
                'classification': classification,
                'is_scanner'    : noise,
                'is_benign'     : riot,
                'description'   : data.get('message', ''),
                'confidence'    : 80 if classification == 'malicious' else 40,
            }
        except Exception:
            return None

    def _heuristic_check(self, ip):
        """
        Basic check when no API key available.
        Uses IP range patterns to identify likely threats.
        """
        parts   = ip.split('.')
        risk    = 'LOW'
        threats = []

        # Known hosting/datacenter ranges
        datacenter_ranges = [
            '45.33.', '104.21.', '172.67.',  # Cloudflare/common VPS
            '23.92.', '23.227.',              # Common VPS providers
        ]
        if any(ip.startswith(r) for r in datacenter_ranges):
            threats.append('datacenter IP — possible VPS attack source')
            risk = 'MEDIUM'

        return {
            'ip'         : ip,
            'is_threat'  : len(threats) > 0,
            'risk'       : risk,
            'source'     : 'heuristic',
            'description': ' | '.join(threats) if threats else 'No known threat',
            'confidence' : 30 if threats else 0,
        }

    def bulk_check(self, ip_list):
        """Check multiple IPs — used with alerts.json."""
        results = {}
        threats_found = 0

        print(f"\n{'='*55}")
        print(f"  THREAT INTELLIGENCE — Checking {len(ip_list)} IPs")
        print(f"{'='*55}")

        for ip in set(ip_list):  # deduplicate
            result = self.check_ip(ip)
            results[ip] = result

            status = '🔴 THREAT' if result['is_threat'] else '🟢 CLEAN '
            print(f"  {status}  {ip:<20} {result['risk']:<8} "
                  f"{result['source']:<12} {result.get('description','')[:35]}")

            if result['is_threat']:
                threats_found += 1

        print(f"{'─'*55}")
        print(f"  Total IPs checked : {len(ip_list)}")
        print(f"  Threats found     : {threats_found}")
        print(f"{'='*55}\n")
        return results


# ── Standalone test ───────────────────────────────────────────
if __name__ == '__main__':
    ti = ThreatIntel()

    # Test IPs — mix of known bad and clean
    test_ips = [
        '45.33.32.156',   # scanme.nmap.org
        '8.8.8.8',        # Google DNS
        '185.220.101.34', # known Tor exit
        '80.82.77.139',   # Shodan scanner
        '130.1.11.127',   # from your capture output
        '142.250.77.138', # Google server
    ]

    # If real alerts exist, use those IPs
    import os
    if os.path.exists('models/alerts.json'):
        with open('models/alerts.json') as f:
            alerts = json.load(f)
        real_ips = list(set(
            [a.get('src','') for a in alerts] +
            [a.get('dst','') for a in alerts]
        ))
        real_ips = [ip for ip in real_ips if ip]
        print(f"Loading {len(real_ips)} IPs from real alerts...\n")
        ti.bulk_check(real_ips)
    else:
        ti.bulk_check(test_ips)