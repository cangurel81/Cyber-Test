from PyQt6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QTextEdit, QMessageBox, QSplitter, QLabel
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon

from gui.test_config import TestConfig
from tests.general_server import GeneralServerTest
from tests.web_server import WebServerTest
from tests.database_server import DatabaseServerTest
from tests.mail_server import MailServerTest
from tests.dns_server import DNSServerTest
from tests.file_server import FileServerTest
from tests.stress_ddos import StressDDOSTest
from tests.port_scanner import PortScannerTest
from utils.reporter import TestReporter

class TestWorker(QThread):
    update_result = pyqtSignal(str)
    test_finished = pyqtSignal(str)

    def __init__(self, params):
        super().__init__()
        self.params = params

    def run(self):
        target = self.params["target"]
        test_type = self.params["test_type"]
        reporter = TestReporter()

        def execute_and_report(test_instance, **kwargs):
            try:
                for name, status, msg in test_instance.run_all_tests(**kwargs):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
            except Exception as e:
                reporter.add_result(test_instance.__class__.__name__, False, str(e))
                result_html = (
                    f"<div style='margin:5px 0; padding:8px; border-left:4px solid #F44336; background-color:#2a2a2a;'>"
                    f"<span style='font-weight:bold;'>❌ {test_instance.__class__.__name__}</span><br>"
                    f"<span style='color:#e0e0e0; margin-left:20px;'>An error occurred: {e}</span>"
                    f"</div>"
                )
                self.update_result.emit(result_html)

        if test_type == "All Tests" or test_type == "General Server Test":
            port = int(self.params.get("general_port", 80))
            general_test = GeneralServerTest(target, port)
            execute_and_report(general_test)

        if test_type == "All Tests" or test_type == "Web Server Test":
            if not target.startswith("http://") and not target.startswith("https://"):
                url = f"http://{target}"
            else:
                url = target
            web_test = WebServerTest(url)
            execute_and_report(web_test)

        if test_type == "All Tests" or test_type == "Stress/DDoS Test":
            port = int(self.params.get("stress_ddos_port", 80))
            packet_count = int(self.params.get("stress_ddos_count", 100))
            interval = float(self.params.get("stress_ddos_interval", 0.01))
            threads = int(self.params.get("stress_ddos_threads", 2))
            monitor_duration = int(self.params.get("stress_ddos_monitor_duration", 10))
            attack_type = self.params.get("stress_ddos_attack_type", "SYN Flood")
            http_method = self.params.get("stress_ddos_http_method", "GET")
            http_path = self.params.get("stress_ddos_http_path", "/")
            udp_size = int(self.params.get("stress_ddos_udp_size", 1024))
            
            stress_test = StressDDOSTest(target, port)
            
            if attack_type == "All Attacks":
                execute_and_report(stress_test, 
                                  syn_count=packet_count, 
                                  syn_interval=interval,
                                  udp_count=packet_count, 
                                  udp_interval=interval,
                                  http_count=packet_count, 
                                  http_interval=max(0.1, interval),
                                  icmp_count=packet_count, 
                                  icmp_interval=interval,
                                  threads=threads,
                                  monitor_duration=monitor_duration,
                                  run_all=True)
            elif attack_type == "SYN Flood":
                execute_and_report(stress_test, 
                                  syn_count=packet_count, 
                                  syn_interval=interval,
                                  threads=threads,
                                  monitor_duration=monitor_duration)
            elif attack_type == "UDP Flood":
                execute_and_report(stress_test, 
                                  udp_count=packet_count, 
                                  udp_interval=interval,
                                  threads=threads,
                                  monitor_duration=monitor_duration,
                                  run_all=False)
                for name, status, msg in stress_test.udp_flood(count=packet_count, 
                                                             interval=interval, 
                                                             threads=threads, 
                                                             packet_size=udp_size):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
            elif attack_type == "HTTP Flood":
                for name, status, msg in stress_test.http_flood(count=packet_count, 
                                                              interval=max(0.1, interval), 
                                                              threads=threads, 
                                                              method=http_method, 
                                                              path=http_path):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                for name, status, msg in stress_test.monitor_system_resources(duration=monitor_duration):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
            elif attack_type == "ICMP Flood":
                for name, status, msg in stress_test.icmp_flood(count=packet_count, 
                                                              interval=interval, 
                                                              threads=threads):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                for name, status, msg in stress_test.monitor_system_resources(duration=monitor_duration):
                    reporter.add_result(name, status, msg)
                    status_icon = "✅" if status else "❌"
                    status_color = "#4CAF50" if status else "#F44336"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} {name}</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)

        if test_type == "All Tests" or test_type == "Database Server Test":
            db_user = self.params.get("db_user", "")
            db_pass = self.params.get("db_pass", "")
            db_name = self.params.get("db_name", "")
            db_test = DatabaseServerTest(target, db_user, db_pass, db_name)
            execute_and_report(db_test)

        if test_type == "All Tests" or test_type == "Mail Server Test":
            smtp_port = int(self.params.get("mail_smtp_port", 25))
            pop3_port = int(self.params.get("mail_pop3_port", 110))
            mail_test = MailServerTest(target, smtp_port=smtp_port, pop3_port=pop3_port)
            execute_and_report(mail_test)

        if test_type == "All Tests" or test_type == "DNS Server Test":
            domain = self.params.get("dns_domain", "google.com")
            dns_test = DNSServerTest(target, domain)
            execute_and_report(dns_test)

        if test_type == "All Tests" or test_type == "File Server Test":
            port = int(self.params.get("file_port", 22))
            username = self.params.get("file_user", "")
            password = self.params.get("file_pass", "")
            file_test = FileServerTest(target, port, username, password)
            execute_and_report(file_test)
            
        if test_type == "All Tests" or test_type == "Port Scanner Test":
            scan_mode = self.params.get("port_scanner_mode", "Manual Range")
            start_port = int(self.params.get("port_scanner_start_port", 1))
            end_port = int(self.params.get("port_scanner_end_port", 1024))
            scan_speed = self.params.get("port_scanner_speed", "Normal")
            service_detection = self.params.get("port_scanner_service_detection", True)
            banner_grabbing = self.params.get("port_scanner_banner_grabbing", True)
            firewall_detection = self.params.get("port_scanner_firewall_detection", True)
            
            use_common_ports = False
            if scan_mode == "Auto (Common Ports)":
                start_port = 1
                end_port = 1024
                use_common_ports = True
            elif scan_mode == "All Ports (1-65535)":
                start_port = 1
                end_port = 65535
            
            if scan_speed == "Slow (Stealthy)":
                speed = "slow"
            elif scan_speed == "Fast (Aggressive)":
                speed = "fast"
            else:
                speed = "normal"
                
            port_scanner = PortScannerTest(target, 
                                          start_port=start_port, 
                                          end_port=end_port, 
                                          scan_speed=speed, 
                                          service_detection=service_detection,
                                          banner_grabbing=banner_grabbing,
                                          firewall_detection=firewall_detection)
            
            if use_common_ports:
                self.update_result.emit("<div style='margin:5px 0; padding:8px; background-color:#2a2a2a;'>"
                                  "<span style='font-weight:bold;'>ℹ️ Scan Mode: Common Ports</span><br>"
                                  "<span style='color:#e0e0e0; margin-left:20px;'>Scanning only common service ports...</span>"
                                  "</div>")
                open_ports, scan_time = port_scanner.scan_common_ports()
                
                if open_ports:
                    port_list = ", ".join([f"{port} ({service})" for port, service in open_ports])
                    reporter.add_result("Port Scan", True, f"{len(open_ports)} open ports found: {port_list} (Scan time: {scan_time:.2f} seconds)")
                    status_icon = "✅"
                    status_color = "#4CAF50"
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid {status_color}; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>{status_icon} Port Scan</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{len(open_ports)} open ports found: {port_list} (Scan time: {scan_time:.2f} seconds)</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                    
                    if banner_grabbing:
                        for port, service in open_ports:
                            banner = port_scanner.banner_grabbing(port)
                            if banner and banner != "Banner not available":
                                reporter.add_result(f"Banner Information (Port {port})", True, f"Service: {service}, Banner: {banner[:100]}...")
                                result_html = (
                                    f"<div style='margin:5px 0; padding:8px; border-left:4px solid #4CAF50; background-color:#2a2a2a;'>"
                                    f"<span style='font-weight:bold;'>✅ Banner Information (Port {port})</span><br>"
                                    f"<span style='color:#e0e0e0; margin-left:20px;'>Service: {service}, Banner: {banner[:100]}...</span>"
                                    f"</div>"
                                )
                                self.update_result.emit(result_html)
                else:
                    reporter.add_result("Port Scan", False, f"No open ports found (Scan time: {scan_time:.2f} seconds)")
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid #F44336; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>❌ Port Scan</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>No open ports found (Scan time: {scan_time:.2f} seconds)</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                
                if firewall_detection:
                    firewall_detected, firewall_msg = port_scanner.detect_firewall()
                    reporter.add_result("Firewall Detection", True, firewall_msg)
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid #4CAF50; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>✅ Firewall Detection</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{firewall_msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                
                if len(open_ports) > 10:
                    security_msg = "HIGH RISK - Multiple open ports detected. It is recommended to close unnecessary ports and implement firewall rules."
                    reporter.add_result("Security Assessment", False, security_msg)
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid #F44336; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>❌ Security Assessment</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{security_msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                elif len(open_ports) > 0:
                    security_msg = "MEDIUM RISK - Some open ports detected. Verify that each service is necessary and properly secured."
                    reporter.add_result("Security Assessment", True, security_msg)
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid #4CAF50; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>✅ Security Assessment</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{security_msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
                else:
                    security_msg = "LOW RISK - No open ports detected. Continue to monitor and maintain your security posture."
                    reporter.add_result("Security Assessment", True, security_msg)
                    result_html = (
                        f"<div style='margin:5px 0; padding:8px; border-left:4px solid #4CAF50; background-color:#2a2a2a;'>"
                        f"<span style='font-weight:bold;'>✅ Security Assessment</span><br>"
                        f"<span style='color:#e0e0e0; margin-left:20px;'>{security_msg}</span>"
                        f"</div>"
                    )
                    self.update_result.emit(result_html)
            else:
                execute_and_report(port_scanner)
            


        report = reporter.generate_report()
        self.test_finished.emit(report)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Test")
        self.setGeometry(100, 100, 400, 800)
        
        # Set security icon
        import os
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "security.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        self.setup_style()
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.central_widget.setLayout(main_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.test_config_page = TestConfig()
        self.test_config_page.start_test_button.clicked.connect(self.run_tests)
        splitter.addWidget(self.test_config_page)
        
        # Results Display Section
        results_container = QWidget()
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(0, 0, 0, 0)
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Consolas", 10))
        self.results_display.setStyleSheet(
            "background-color: #2b2b2b; color: #f0f0f0; border-radius: 5px; padding: 10px;"
        )
        results_layout.addWidget(self.results_display)
        
        splitter.addWidget(results_container)
        
        # Set initial sizes for splitter
        splitter.setSizes([400, 400])
        
        main_layout.addWidget(splitter)
        
        # Footer
        footer_label = QLabel("WebAdHere Software")
        footer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer_label.setStyleSheet("""
            QLabel {
                color: #888888;
                font-size: 10px;
                font-style: italic;
                padding: 5px;
                border-top: 1px solid #555555;
                margin-top: 5px;
            }
        """)
        main_layout.addWidget(footer_label)

        self.test_worker = None



    def setup_style(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Base, QColor(42, 42, 42))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(66, 66, 66))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        self.setPalette(palette)
        
        # Set stylesheet for the entire application
        self.setStyleSheet("""
            QWidget {
                background-color: #353535;
                color: #ffffff;
            }
            QTextEdit, QLineEdit, QComboBox {
                border: 1px solid #5a5a5a;
                border-radius: 4px;
                padding: 2px 4px;
                background-color: #2a2a2a;
                color: #ffffff;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox::down-arrow {
                width: 14px;
                height: 14px;
            }
            QPushButton {
                background-color: #0d6efd;
                color: white;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0b5ed7;
            }
            QPushButton:pressed {
                background-color: #0a58ca;
            }
            QLabel {
                font-weight: bold;
            }
        """)
        
    def run_tests(self):
        if self.test_worker and self.test_worker.isRunning():
            QMessageBox.warning(self, "Test in Progress", "A test is already running. Please wait for it to complete.")
            return

        params = self.test_config_page.get_test_parameters()
        if not params.get("target"):
            QMessageBox.warning(self, "Input Error", "Please enter a target IP address or website URL.")
            return

        self.results_display.clear()
        self.results_display.append(f"<div style='background-color:#2d4b2d; color:#ffffff; padding:10px; border-radius:5px; margin-bottom:10px;'>"
                               f"<span style='font-size:14px; font-weight:bold;'>🚀 Starting {params['test_type']} for {params['target']}...</span>"
                               f"</div>")
        
        self.test_config_page.start_test_button.setEnabled(False)
        self.test_config_page.start_test_button.setText("Testing...")

        self.test_worker = TestWorker(params)
        self.test_worker.update_result.connect(self.update_results_display)
        self.test_worker.test_finished.connect(self.test_finished)
        self.test_worker.start()

    def update_results_display(self, result_html):
        self.results_display.append(result_html)

    def test_finished(self, final_report):
        self.results_display.append(f"<div style='background-color:#4f4f4f; color:#ffffff; padding:10px; border-radius:5px; margin-top:10px;'>"
                               f"<span style='font-size:14px; font-weight:bold;'>🏁 Tests Finished!</span>"
                               f"</div>")
        # The detailed report is now optional as results are shown in real-time.
        # self.results_display.append(final_report.replace('\n', '<br>'))
        self.test_config_page.start_test_button.setEnabled(True)
        self.test_config_page.start_test_button.setText("Start Test")