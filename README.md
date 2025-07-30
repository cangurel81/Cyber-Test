# 🔐 Cyber Test - Comprehensive Server Security Testing Suite

**Cyber Test** is a professional Python application designed for comprehensive security testing of servers and network infrastructure. With its modern PyQt6-based interface, security professionals and system administrators can easily perform various security assessments and penetration testing tasks.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 🌟 Features

### 🖥️ Server Testing Modules

#### 🌐 **Web Server Security Testing**
- **HTTP/HTTPS Connectivity**: Complete connection testing and protocol analysis
- **Security Headers Analysis**: Comprehensive security headers validation
- **SSL/TLS Security Assessment**: Certificate validation, protocol analysis, and encryption strength testing
- **Vulnerability Scanning**:
  - XSS (Cross-Site Scripting) detection
  - SQL Injection vulnerability testing
  - Open Redirect vulnerability checks
  - Directory traversal testing
- **Directory Discovery**: Common paths and hidden directories enumeration

#### 🗄️ **Database Server Testing**
- **Multi-Database Support**: MySQL, PostgreSQL, SQL Server connectivity
- **Authentication Testing**: Credential validation and brute force protection
- **Connection Security**: Encryption and secure connection analysis
- **Basic Query Performance**: Response time and availability testing

#### 📧 **Mail Server Security Assessment**
- **Protocol Testing**: SMTP, POP3, IMAP connectivity and security
- **Authentication Mechanisms**: Login security and credential testing
- **Open Relay Detection**: Mail relay vulnerability assessment
- **Security Configuration**: Mail server hardening verification

#### 🌍 **DNS Server Analysis**
- **DNS Resolution Testing**: Query response and performance analysis
- **Zone Transfer Attempts**: DNS security misconfiguration detection
- **DNS Security**: DNSSEC validation and security assessment

#### 📁 **File Server Security Testing**
- **Multi-Protocol Support**: SMB, FTP, SSH/SFTP connectivity
- **Authentication Security**: Access control and credential testing
- **File Integrity Checks**: Data security and access permission analysis

#### 🔍 **Advanced Port Scanner**
- **Intelligent Scanning Modes**:
  - Auto (Common Ports): Fast scanning of frequently used ports
  - Manual Range: Custom port range specification
  - Full Scan: Complete 1-65535 port range scanning
- **Service Detection**: Automatic service identification and version detection
- **Banner Grabbing**: Service banner collection and analysis
- **Firewall Detection**: Network security device identification
- **Security Assessment**: Risk evaluation based on open ports
- **Performance Optimization**: Multi-threaded scanning with speed control

### ⚡ **Stress Testing & DDoS Simulation**

#### 💥 **Attack Simulation Capabilities**
- **SYN Flood Attacks**: TCP SYN flood simulation for resilience testing
- **UDP Flood Attacks**: UDP packet flooding with customizable payload sizes
- **HTTP Flood Attacks**: Application-layer DDoS simulation with various HTTP methods
- **ICMP Flood Attacks**: Network-layer ping flood testing
- **Multi-Vector Attacks**: Combined attack scenarios for comprehensive testing

#### 📊 **System Monitoring**
- **Real-time Resource Monitoring**: CPU and memory usage tracking during tests
- **Performance Metrics**: Response time and availability monitoring
- **Attack Impact Assessment**: System behavior analysis under stress conditions

### 🎨 **Modern User Interface**

#### 🖼️ **GUI Features**
- **Dark Theme**: Professional dark interface for extended use
- **Real-time Results**: Live test progress and results display
- **Intuitive Configuration**: Easy-to-use test parameter setup
- **Multi-threaded Execution**: Non-blocking UI during test execution
- **Comprehensive Reporting**: Detailed test results with color-coded status indicators

#### 📋 **Test Configuration**
- **Target Flexibility**: Support for IP addresses and domain names
- **Parameter Customization**: Extensive configuration options for each test type
- **Batch Testing**: Multiple test types execution in sequence
- **Export Capabilities**: Test results export and reporting

## 🛠️ **Technology Stack**

- **Core Language**: Python 3.8+
- **GUI Framework**: PyQt6 (Modern, cross-platform interface)
- **Network Libraries**: 
  - `scapy` - Advanced packet manipulation and network analysis
  - `requests` - HTTP/HTTPS communication
  - `paramiko` - SSH/SFTP connectivity
  - `dnspython` - DNS operations and analysis
- **Database Connectivity**: `pymysql`, `psycopg2`, `pyodbc`
- **System Monitoring**: `psutil` - System resource monitoring
- **Security**: Built-in security best practices and ethical testing guidelines

## 📁 **Project Structure**

```
cyber-test/
├── main.py                 # Application entry point
├── gui/                    # User interface modules
│   ├── __init__.py
│   ├── main_window.py      # Main application window with dark theme
│   └── test_config.py      # Advanced test configuration interface
├── tests/                  # Core testing modules
│   ├── __init__.py
│   ├── general_server.py   # General connectivity and basic tests
│   ├── web_server.py       # Web security testing suite
│   ├── database_server.py  # Database connectivity and security
│   ├── mail_server.py      # Mail server security assessment
│   ├── dns_server.py       # DNS security and performance testing
│   ├── file_server.py      # File server security evaluation
│   ├── stress_ddos.py      # Stress testing and DDoS simulation
│   └── port_scanner.py     # Advanced port scanning capabilities
├── utils/                  # Utility modules
│   ├── __init__.py
│   ├── logger.py          # Comprehensive logging system
│   └── reporter.py        # Advanced reporting and export features
├── requirements.txt        # Python dependencies
└── README.md              # Project documentation
```

## 🚀 **Installation & Setup**

### **Prerequisites**
- Python 3.8 or higher
- Administrator/root privileges (required for some network operations)
- Network access to target systems

### **Quick Start**

1. **Clone the repository**:
```bash
git clone https://github.com/cangurel81/cyber-test.git
cd cyber-test
```

2. **Create virtual environment** (recommended):
```bash
python -m venv venv
```

3. **Activate virtual environment**:
```bash
# Windows
.\venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

4. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Run the application**:
```bash
python main.py
```

## 📋 **Dependencies**

```
PyQt6>=6.0.0           # Modern GUI framework
requests>=2.25.0       # HTTP/HTTPS communication
paramiko>=2.7.0        # SSH/SFTP connectivity
dnspython>=2.1.0       # DNS operations
scapy>=2.4.0          # Network packet manipulation
psutil>=5.8.0         # System resource monitoring
pymysql>=1.0.0        # MySQL database connectivity
psycopg2-binary>=2.8.0 # PostgreSQL database connectivity
pyodbc>=4.0.0         # SQL Server database connectivity
```

<img width="415" height="842" alt="Ekran görüntüsü 2025-07-30 194552" src="https://github.com/user-attachments/assets/a610aee7-772b-47d0-9473-d24c3b83449f" />

## 🎯 **Usage Examples**

### **Basic Web Security Scan**
1. Select "Web Server Test" from the test type dropdown
2. Enter target URL (e.g., `https://example.com`)
3. Click "Start Test" to begin comprehensive web security assessment

### **Port Scanning**
1. Choose "Port Scanner Test"
2. Select scanning mode (Auto/Manual/Full)
3. Configure additional options (service detection, banner grabbing)
4. Execute scan and review detailed results

### **Stress Testing**
1. Select "Stress/DDoS Test"
2. Choose attack type (SYN Flood, UDP Flood, HTTP Flood, ICMP Flood)
3. Configure parameters (packet count, interval, threads)
4. Monitor real-time system impact

## ⚠️ **Important Security Notice**

### **Ethical Use Only**
- This tool is designed for **authorized security testing only**
- Only use on systems you own or have explicit written permission to test
- Follow responsible disclosure practices for any vulnerabilities discovered
- Comply with all applicable laws and regulations in your jurisdiction

### **Legal Disclaimer**
- Users are solely responsible for ensuring lawful use of this software
- The developers assume no liability for misuse or illegal activities
- This tool is provided for educational and legitimate security testing purposes

## 🤝 **Contributing**

We welcome contributions! Please feel free to:
- Report bugs and issues
- Suggest new features
- Submit pull requests
- Improve documentation

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 **Security & Privacy**

- No data is transmitted to external servers
- All tests are performed locally
- User credentials and sensitive data are handled securely
- Test results are stored locally only

---

**⭐ Star this repository if you find it useful!**

For questions, issues, or feature requests, please open an issue on GitHub.
