# IKE-Hunter v1.0 - Advanced IKE/VPN Security Assessment Tool

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)
![Status](https://img.shields.io/badge/status-production-success.svg)

**IKE-Hunter** is a comprehensive IKE/IPSec vulnerability scanner designed for penetration testers and security professionals. Built to identify VPN infrastructure weaknesses, cipher vulnerabilities, and known CVE patterns across enterprise networks.

## 🎯 What Makes IKE-Hunter Special

IKE-Hunter goes beyond basic IKE scanning with advanced vulnerability detection and enterprise-ready assessment capabilities:

### 🔍 **Comprehensive Vulnerability Detection**
- **20+ CVE Patterns** - Critical vulnerabilities from 2002-2021
- **Vendor-Specific Detection** - Cisco ASA/IOS, SonicWall, VMware NSX
- **Crypto Weakness Analysis** - DES, 3DES, MD5, weak DH groups
- **Attack Vector Mapping** - DoS, info disclosure, PSK brute force

### 🚀 **Advanced Assessment Features**
- **Multi-Threading** - Concurrent scanning for enterprise networks
- **Transform Set Testing** - 9 cipher combinations from strong to legacy
- **Aggressive Mode Detection** - PSK vulnerability assessment
- **Security Level Classification** - Secure/Moderate/Permissive/Weak ratings

### 📊 **Professional Reporting**
- **JSON Output** - Structured data for automation and SIEM integration
- **Real-time Progress** - Live scan status with emoji indicators
- **Vulnerability Mapping** - CVE details with severity ratings
- **Executive Summaries** - High-level security assessments

### 🎯 **Enterprise-Ready Architecture**
- **CIDR Range Support** - Intelligent sampling for large networks
- **ike-scan Integration** - Reliable IKE protocol testing
- **Timeout Handling** - Robust error recovery and network resilience
- **Threaded Execution** - Scalable performance for large assessments

## 🔧 Key Enhancements from Basic IKE Scanning

| Feature | Basic IKE-Scan | IKE-Hunter v1.0 |
|---------|----------------|------------------|
| **CVE Detection** | None | 20+ Critical CVEs |
| **Vendor Identification** | Limited | Cisco, SonicWall, VMware NSX |
| **Threading** | Single-threaded | Multi-threaded (configurable) |
| **Crypto Analysis** | Basic | Comprehensive weakness detection |
| **Reporting** | Text only | JSON + Executive summaries |
| **CIDR Scanning** | Manual | Intelligent sampling |
| **Vulnerability Assessment** | None | 4-level security rating |
| **Attack Vectors** | Limited | DoS, PSK brute force, crypto attacks |

## 📦 Installation

### Prerequisites
```bash
# Install ike-scan (required dependency)
sudo apt update
sudo apt install ike-scan

# Verify installation
ike-scan --help
```

### Quick Install
```bash
git clone https://github.com/lokii-git/ike-hunter.git
cd ike-hunter
python3 ike-hunter.py --help
```

### System-wide Installation (Optional)
```bash
# Install system-wide
sudo cp ike-hunter.py /usr/local/bin/ike-hunter
sudo chmod +x /usr/local/bin/ike-hunter

# Test installation
ike-hunter --help
```

## 🎯 Usage Examples

### Single Target Assessment
```bash
# Basic VPN gateway scan
python3 ike-hunter.py 192.168.1.1

# Quick scan with fewer transforms
python3 ike-hunter.py 10.0.0.1 --quick

# Custom threading and timeout
python3 ike-hunter.py vpn.company.com -t 10 --timeout 10
```

### Enterprise Network Assessment
```bash
# Scan entire VPN infrastructure
python3 ike-hunter.py 192.168.1.0/24

# Multiple targets from file
python3 ike-hunter.py targets.txt -t 15

# Large-scale assessment with custom output
python3 ike-hunter.py company-vpns.txt -o security_assessment.json
```

### Advanced Security Testing
```bash
# CIDR range with intelligent sampling
python3 ike-hunter.py 10.0.0.0/16 -t 20

# Custom report location
python3 ike-hunter.py internal-vpns.txt -o /reports/ike-assessment-2026.json

# High-speed scanning for time-sensitive assessments
python3 ike-hunter.py target-list.txt -t 25 --timeout 3
```

### Real-World Example Output
```
🎯 IKE-Hunter Results for 192.168.1.100
======================================================================
✅ Target responsive: True
🔐 Security Level: WEAK
🧪 Transforms Tested: 9
⚠️  Accepted Transforms: DES, 3DES-MD5, AES-128-MD5

📊 Detailed Results:
   ❌ DES: accepts_connections
      └── Notify message 36136 (INVALID-PAYLOAD-TYPE)
   ❌ 3DES-MD5: accepts_connections
      └── Notify message 14 (NO-PROPOSAL-CHOSEN)
   ⚠️ AES-128-MD5: properly_configured
   ✅ Aggressive Mode: potentially_vulnerable
      └── CVE-2002-1623: IKE aggressive mode pre-shared key vulnerability
======================================================================
```

## 🔍 Vulnerability Database

### Critical CVEs Detected
- **CVE-2002-1623**: IKE aggressive mode PSK vulnerability (High)
- **CVE-2016-7553**: IKE buffer overflow vulnerability (Critical) 
- **CVE-2018-0147**: Cisco ASA IKEv1 DoS vulnerability (High)
- **CVE-2021-1585**: Cisco ASA IKEv1 and IKEv2 DoS vulnerability (High)

### Vendor-Specific Vulnerabilities
- **Cisco ASA**: 6 major CVEs covering IKEv1/IKEv2 DoS and fragments
- **SonicWall SonicOS**: IKE DoS vulnerabilities
- **VMware NSX**: IKE service crash vulnerabilities
- **Cisco IOS/IOS-XE**: IKEv2 malformed packet DoS

### Crypto Weakness Detection
- **Weak Encryption**: DES, 3DES detection with risk assessment
- **Weak Hashing**: MD5 algorithm identification
- **Weak DH Groups**: DH Group 1 and 2 vulnerability detection
- **PSK Brute Force**: Aggressive mode PSK cracking potential

## 📊 Output Formats

### Console Output (Real-time)
```
🎯 Scanning 192.168.1.100...
   └── Testing AES-256...
   └── Testing AES-128...
   └── Testing 3DES...
   └── Testing Aggressive Mode...

✅ 192.168.1.100: weak
❌ 192.168.1.101: not_responsive  
⚠️ 192.168.1.102: moderate
```

### JSON Report (Automation)
```json
{
  "tool": "ike-hunter",
  "version": "1.0",
  "timestamp": "2026-01-21T12:34:56",
  "summary": {
    "total_targets": 3,
    "responsive_targets": 2,
    "vulnerable_targets": 1
  },
  "results": [{
    "target": "192.168.1.100",
    "summary": {
      "security_level": "weak",
      "accepted_transforms": ["DES", "3DES-MD5"],
      "responsive": true
    },
    "vulnerabilities": [
      {
        "cve": "CVE-2002-1623",
        "severity": "high",
        "description": "IKE aggressive mode pre-shared key vulnerability"
      }
    ]
  }]
}
```

## 🛠️ Command Line Options

```
Usage: ike-hunter.py [-h] [-t THREADS] [-o OUTPUT] [--timeout TIMEOUT] [--quick] target

Arguments:
  target                Target IP, CIDR range, or file containing targets

Options:
  -h, --help           Show help message and exit
  -t, --threads        Number of threads (default: 5)
  -o, --output         Output report file (JSON format)
  --timeout            Timeout per scan in seconds (default: 5)
  --quick              Quick scan (fewer transforms for speed)
```

## 🎯 Use Cases

### Penetration Testing
- **VPN Infrastructure Assessment** - Identify vulnerable IPSec gateways
- **Cipher Strength Analysis** - Detect weak encryption and hashing
- **CVE Vulnerability Scanning** - Find known security flaws
- **Attack Surface Mapping** - Catalog all accessible VPN endpoints

### Security Auditing
- **Compliance Validation** - Ensure strong crypto standards
- **Risk Assessment** - Quantify VPN security posture
- **Vendor Security Review** - Identify vendor-specific vulnerabilities
- **Configuration Analysis** - Detect insecure IKE configurations

### Network Discovery
- **VPN Endpoint Enumeration** - Find all IKE-responsive hosts
- **Corporate Infrastructure Mapping** - Identify remote access points
- **Third-party VPN Detection** - Discover partner/vendor connections
- **Shadow IT Identification** - Locate unauthorized VPN deployments

## 🔒 Security Considerations

### Responsible Usage
- **Authorized Testing Only** - Obtain proper permission before scanning
- **Rate Limiting** - Use appropriate threading to avoid DoS
- **Legal Compliance** - Follow local laws and regulations
- **Data Protection** - Secure scan results and target information

### Detection Avoidance
- **Stealth Scanning** - Use conservative timeouts and thread counts
- **Randomization** - Vary scan timing and patterns
- **Legitimate Traffic** - IKE scans appear as normal VPN negotiation attempts
- **Minimal Footprint** - No exploitation, only vulnerability identification

## 🙏 Credits & Attribution

**IKE-Hunter v1.0** - Advanced IKE/VPN Security Assessment

- **Tool Development** by [@lokii-git](https://github.com/lokii-git)
- **IKE Protocol Testing** powered by [ike-scan](https://github.com/royhills/ike-scan)
- **CVE Research** compiled from public vulnerability databases
- **Security Community** contributions and feedback

This tool builds upon the excellent ike-scan foundation while adding modern vulnerability detection capabilities for today's enterprise VPN assessments.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**IKE-Hunter v1.0** - Professional VPN security assessment for modern penetration testing 🛡️

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

**⚠️ Disclaimer**: This tool is for authorized penetration testing and security research only. Users are responsible for complying with applicable laws and regulations.