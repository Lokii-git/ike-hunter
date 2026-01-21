#!/usr/bin/env python3
"""
IKE-Hunter - Advanced IKE/VPN Security Assessment Tool
Usage: python3 ike-hunter.py [options] target(s)
Author: Philip Burnham @Lokii-git
"""

import argparse
import json
import os
import sys
import subprocess
import ipaddress
import random
import time
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# =============================================================================
# CONFIGURATION
# =============================================================================
IKE_PORT = 500
MAX_THREADS = 10
TIMEOUT = 5

# Common IKE transforms to test (Encryption, Hash, DH Group, Auth)
TRANSFORM_SETS = [
    # Strong modern ciphers
    ("AES-256", "8,2,14,2"),    # AES-256, HMAC-SHA, DH Group 14, SHA-1
    ("AES-256-SHA256", "8,12,14,12"),  # AES-256, HMAC-SHA256, DH Group 14, SHA-256
    ("AES-192", "6,2,14,2"),    # AES-192, HMAC-SHA, DH Group 14, SHA-1
    ("AES-128", "7,2,14,2"),    # AES-128, HMAC-SHA, DH Group 14, SHA-1
    
    # Common ciphers
    ("AES-128-MD5", "7,4,2,2"), # AES-128, HMAC-MD5, DH Group 2, SHA-1
    ("AES-128-SHA", "7,2,2,2"), # AES-128, HMAC-SHA, DH Group 2, SHA-1
    
    # Legacy/weak ciphers (for vulnerability detection)
    ("3DES", "5,2,1,2"),        # 3DES-CBC, HMAC-SHA, DH Group 1, SHA-1
    ("3DES-MD5", "5,4,1,2"),    # 3DES-CBC, HMAC-MD5, DH Group 1, SHA-1
    ("DES", "1,2,1,2"),         # DES-CBC, HMAC-SHA, DH Group 1, SHA-1 (very weak)
]

# Known CVE patterns and signatures
CVE_PATTERNS = {
    # Critical IKE/IPSec vulnerabilities
    "CVE-2016-7553": {
        "description": "IKE buffer overflow vulnerability",
        "indicators": ["aggressive_mode_response", "malformed_payload"],
        "severity": "critical"
    },
    "CVE-2018-5389": {
        "description": "IKEv1 information disclosure",
        "indicators": ["vendor_id_disclosure", "implementation_details"],
        "severity": "medium"
    },
    "CVE-2002-1623": {
        "description": "IKE aggressive mode pre-shared key vulnerability",
        "indicators": ["aggressive_mode", "psk_hash_capture"],
        "severity": "high"
    },
    "CVE-2018-0147": {
        "description": "Cisco ASA IKEv1 DoS vulnerability", 
        "indicators": ["cisco_asa", "ikev1_dos_response"],
        "severity": "high"
    },
    "CVE-2018-0296": {
        "description": "Cisco ASA IKEv2 fragmentation DoS",
        "indicators": ["cisco_asa", "ikev2_fragmentation"],
        "severity": "high"
    },
    "CVE-2019-1653": {
        "description": "Cisco Small Business VPN router information disclosure",
        "indicators": ["cisco_sb", "config_disclosure"],
        "severity": "medium"
    },
    "CVE-2020-3433": {
        "description": "Cisco ASA IKEv2 DoS vulnerability",
        "indicators": ["cisco_asa", "ikev2_dos"],
        "severity": "medium"
    },
    "CVE-2021-1585": {
        "description": "Cisco ASA IKEv1 and IKEv2 DoS vulnerability",
        "indicators": ["cisco_asa", "ike_dos_both_versions"],
        "severity": "high"
    },
    "CVE-2017-6742": {
        "description": "Cisco ASA IKEv1 invalid fragment handling",
        "indicators": ["cisco_asa", "ikev1_fragment_vuln"],
        "severity": "medium"
    },
    "CVE-2016-6415": {
        "description": "SonicWall SonicOS IKE DoS vulnerability",
        "indicators": ["sonicwall", "ike_dos_response"],
        "severity": "medium"
    },
    "CVE-2018-6961": {
        "description": "VMware NSX IKE service DoS",
        "indicators": ["vmware_nsx", "ike_service_crash"],
        "severity": "medium"
    },
    "CVE-2019-11478": {
        "description": "TCP SACK panic (affects VPN implementations)",
        "indicators": ["tcp_sack_panic", "kernel_panic"],
        "severity": "high"
    },
    "CVE-2018-0329": {
        "description": "Cisco IOS IKEv2 DoS vulnerability",
        "indicators": ["cisco_ios", "ikev2_malformed_packet"],
        "severity": "medium"
    },
    "CVE-2017-12240": {
        "description": "Cisco ASA IKEv1 DoS via malformed packet",
        "indicators": ["cisco_asa", "ikev1_malformed_dos"],
        "severity": "medium"
    },
    "CVE-2020-3191": {
        "description": "Cisco IOS XE IKEv2 DoS vulnerability",
        "indicators": ["cisco_ios_xe", "ikev2_dos"],
        "severity": "medium"
    },
    
    # Generic vulnerability patterns
    "WEAK_DH_GROUPS": {
        "description": "Weak Diffie-Hellman groups (DH1, DH2)",
        "indicators": ["dh_group_1", "dh_group_2", "weak_dh"],
        "severity": "medium"
    },
    "WEAK_ENCRYPTION": {
        "description": "Weak encryption algorithms (DES, 3DES)",
        "indicators": ["des_encryption", "3des_encryption"],
        "severity": "medium"
    },
    "WEAK_HASH": {
        "description": "Weak hash algorithms (MD5)",
        "indicators": ["md5_hash", "weak_hash_algo"],
        "severity": "low"
    },
    "PSK_BRUTE_FORCE": {
        "description": "Pre-shared key vulnerable to brute force",
        "indicators": ["aggressive_mode", "psk_discoverable"],
        "severity": "high"
    }
}

class IKEHunter:
    def __init__(self):
        self.results = []
        self.vulnerabilities = []
        self.lock = threading.Lock()
        
    def load_targets(self, target_input):
        """Load targets from file, IP, or CIDR range"""
        targets = []
        
        # Check if it's a file
        if os.path.isfile(target_input):
            with open(target_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.extend(self._parse_target(line))
        else:
            # Single target or CIDR
            targets.extend(self._parse_target(target_input))
            
        return list(set(targets))  # Remove duplicates
    
    def _parse_target(self, target):
        """Parse individual target (IP or CIDR)"""
        targets = []
        
        try:
            # Try as CIDR range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
                
                if len(hosts) <= 10:
                    # Small range, scan all
                    targets.extend([str(ip) for ip in hosts])
                else:
                    # Large range, sample 10 random IPs
                    sampled = random.sample(hosts, 10)
                    targets.extend([str(ip) for ip in sampled])
            else:
                # Single IP
                ipaddress.ip_address(target)  # Validate
                targets.append(target)
                
        except ValueError:
            print(f"Invalid target format: {target}")
            
        return targets
    
    def run_ike_scan(self, target, transform=None, mode="main"):
        """Execute ike-scan with specified parameters"""
        cmd = ["ike-scan"]
        
        if mode == "aggressive":
            cmd.append("-A")
        else:
            cmd.append("-M")  # Main mode
            
        if transform:
            cmd.extend(["--trans", transform])
            
        cmd.extend(["--showbackoff", "--retry", "2", target])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
            return {
                'target': target,
                'command': ' '.join(cmd),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                'target': target,
                'command': ' '.join(cmd),
                'error': 'Timeout',
                'success': False
            }
        except FileNotFoundError:
            return {
                'target': target,
                'error': 'ike-scan not found - install with: apt install ike-scan',
                'success': False
            }
        except Exception as e:
            return {
                'target': target,
                'error': str(e),
                'success': False
            }
    
    def analyze_response(self, scan_result):
        """Analyze IKE scan response for interesting findings"""
        if not scan_result.get('success') or not scan_result.get('stdout'):
            return None
            
        stdout = scan_result['stdout']
        target = scan_result['target']
        
        analysis = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'responsive': False,
            'handshake_success': False,
            'notify_messages': [],
            'vendor_ids': [],
            'certificates': [],
            'vulnerabilities': [],
            'security_assessment': 'unknown'
        }
        
        # Check if target is responsive
        if "returned notify" in stdout or "returned handshake" in stdout:
            analysis['responsive'] = True
            
        # Parse notify messages
        for line in stdout.split('\n'):
            if "Notify message" in line:
                analysis['notify_messages'].append(line.strip())
                
        # Check for successful handshakes
        if "returned handshake" in stdout and not "0 returned handshake" in stdout:
            analysis['handshake_success'] = True
            analysis['security_assessment'] = 'potentially_vulnerable'
            
        # Look for vendor IDs or implementation details
        if "VID" in stdout or "vendor" in stdout.lower():
            for line in stdout.split('\n'):
                if "VID" in line:
                    analysis['vendor_ids'].append(line.strip())
                    
        # Security assessment
        if not analysis['responsive']:
            analysis['security_assessment'] = 'not_responsive'
        elif analysis['handshake_success']:
            analysis['security_assessment'] = 'accepts_connections'
        elif analysis['notify_messages']:
            analysis['security_assessment'] = 'properly_configured'
            
        return analysis
    
    def comprehensive_scan(self, target):
        """Perform comprehensive IKE assessment on target"""
        print(f"🎯 Scanning {target}...")
        
        target_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': [],
            'summary': {},
            'vulnerabilities': []
        }
        
        # Test different transform sets
        responsive = False
        accepted_transforms = []
        
        for transform_name, transform_code in TRANSFORM_SETS:
            print(f"   └── Testing {transform_name}...")
            
            scan_result = self.run_ike_scan(target, transform_code)
            analysis = self.analyze_response(scan_result)
            
            if analysis and analysis['responsive']:
                responsive = True
                
            if analysis and analysis['handshake_success']:
                accepted_transforms.append(transform_name)
                
            target_results['scans'].append({
                'transform': transform_name,
                'scan': scan_result,
                'analysis': analysis
            })
            
        # Test aggressive mode if responsive
        if responsive:
            print(f"   └── Testing Aggressive Mode...")
            aggressive_result = self.run_ike_scan(target, mode="aggressive")
            aggressive_analysis = self.analyze_response(aggressive_result)
            
            target_results['scans'].append({
                'transform': 'Aggressive Mode',
                'scan': aggressive_result,
                'analysis': aggressive_analysis
            })
            
        # Compile summary
        target_results['summary'] = {
            'responsive': responsive,
            'accepted_transforms': accepted_transforms,
            'total_transforms_tested': len(TRANSFORM_SETS)
        }
        
        # Add security level assessment
        target_results['summary']['security_level'] = self._assess_security_level(responsive, accepted_transforms)
        
        return target_results
    
    def _assess_security_level(self, responsive, accepted_transforms):
        """Assess overall security level based on scan results"""
        if not responsive:
            return 'not_responsive'
            
        if not accepted_transforms:
            return 'secure'  # Rejects all standard proposals
        elif any('DES' in t or 'MD5' in t for t in accepted_transforms):
            return 'weak'    # Accepts weak ciphers
        elif len(accepted_transforms) > 3:
            return 'permissive'  # Accepts many different ciphers
        else:
            return 'moderate'    # Selective cipher acceptance
    
    def display_results(self, target_results):
        """Display formatted results for a target"""
        target = target_results['target']
        summary = target_results['summary']
        
        print(f"\n{'='*70}")
        print(f"🎯 IKE-Hunter Results for {target}")
        print(f"{'='*70}")
        
        if not summary['responsive']:
            print(f"❌ Target not responsive on port {IKE_PORT}/UDP")
            return
            
        print(f"✅ Target responsive: {summary['responsive']}")
        print(f"🔐 Security Level: {summary['security_level'].upper()}")
        print(f"🧪 Transforms Tested: {summary['total_transforms_tested']}")
        
        if summary['accepted_transforms']:
            print(f"⚠️  Accepted Transforms: {', '.join(summary['accepted_transforms'])}")
        else:
            print(f"🛡️  No standard transforms accepted (good security posture)")
            
        # Show detailed scan results
        print(f"\n📊 Detailed Results:")
        for scan in target_results['scans']:
            if scan['analysis'] and scan['analysis']['responsive']:
                status = "✅" if scan['analysis']['handshake_success'] else "⚠️"
                print(f"   {status} {scan['transform']}: {scan['analysis']['security_assessment']}")
                
                for notify in scan['analysis']['notify_messages']:
                    print(f"      └── {notify}")
                    
        print(f"{'='*70}")
    
    def save_report(self, all_results, filename="ike_hunter_report.json"):
        """Save comprehensive JSON report"""
        report = {
            'tool': 'ike-hunter',
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_targets': len(all_results),
                'responsive_targets': len([r for r in all_results if r['summary']['responsive']]),
                'vulnerable_targets': len([r for r in all_results if r['summary']['security_level'] in ['weak', 'permissive']])
            },
            'results': all_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n💾 Full report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description="IKE-Hunter - Advanced IKE/VPN Security Assessment Tool")
    parser.add_argument('target', help='Target IP, CIDR range, or file containing targets')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', default='ike_hunter_report.json', help='Output report file')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout per scan (seconds)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (fewer transforms)')
    args = parser.parse_args()
    
    # ASCII Art Banner
    print(r"""
_ _  _ ____    _  _ _  _ _  _ ___ ____ ____ 
| |_/  |___ __ |__| |  | |\ |  |  |___ |__/ 
| | \_ |___    |  | |__| | \|  |  |___ |  \ 
                                            
    Advanced IKE/VPN Security Assessment
          @Lokii-git
    """)
    
    hunter = IKEHunter()
    
    # Load targets
    print(f"🔍 Loading targets from: {args.target}")
    targets = hunter.load_targets(args.target)
    
    if not targets:
        print("❌ No valid targets found")
        sys.exit(1)
        
    print(f"📍 Found {len(targets)} targets to scan")
    
    # Perform scans
    all_results = []
    
    if len(targets) == 1:
        # Single target - detailed output
        result = hunter.comprehensive_scan(targets[0])
        hunter.display_results(result)
        all_results.append(result)
    else:
        # Multiple targets - threaded scanning
        print(f"\n🚀 Starting threaded scan with {args.threads} threads...")
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_target = {executor.submit(hunter.comprehensive_scan, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    
                    # Brief summary for multi-target
                    status = result['summary']['security_level']
                    responsive = "✅" if result['summary']['responsive'] else "❌"
                    print(f"   {responsive} {target}: {status}")
                    
                except Exception as e:
                    print(f"   ❌ {target}: Error - {e}")
    
    # Save report
    hunter.save_report(all_results, args.output)
    
    # Final summary
    responsive = len([r for r in all_results if r['summary']['responsive']])
    vulnerable = len([r for r in all_results if r['summary']['security_level'] in ['weak', 'permissive']])
    
    print(f"\n📈 Scan Summary:")
    print(f"   Total Targets: {len(targets)}")
    print(f"   Responsive: {responsive}")
    print(f"   Potentially Vulnerable: {vulnerable}")
    print(f"   Report: {args.output}")

if __name__ == "__main__":
    main()