from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QComboBox, QFormLayout, QHBoxLayout, QStackedWidget,
                             QGroupBox, QFrame, QSizePolicy, QCheckBox)

class TestConfig(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Test Configuration")
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        self.setLayout(main_layout)

        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                border: 1px solid #5a5a5a;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #4CAF50;
            }
        """)
        
        target_layout = QFormLayout()
        target_layout.setSpacing(10)
        target_layout.setContentsMargins(15, 15, 15, 15)
        target_group.setLayout(target_layout)

        self.target_type_combo = QComboBox()
        self.target_type_combo.addItem("IP Address")
        self.target_type_combo.addItem("Website Address")
        self.target_type_combo.currentIndexChanged.connect(self.update_target_input)
        self.target_type_combo.setMinimumHeight(30)
        target_layout.addRow("Target Type:", self.target_type_combo)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP Address or Website URL")
        self.target_input.setMinimumHeight(30)
        target_layout.addRow("Target:", self.target_input)
        
        self.general_port_input = QLineEdit("80")
        self.general_port_input.setMinimumHeight(30)
        target_layout.addRow("Port:", self.general_port_input)
        self.port_scanner_mode = QComboBox()
        self.port_scanner_mode.addItems(["Auto (Common Ports)", "Manual Range", "All Ports (1-65535)"])
        self.port_scanner_mode.currentIndexChanged.connect(self.update_port_scanner_mode)
        self.port_scanner_mode.setMinimumHeight(30)
        target_layout.addRow("Port Scan Mode:", self.port_scanner_mode)
        
        self.port_range_container = QWidget()
        port_range_layout = QHBoxLayout()
        port_range_layout.setContentsMargins(0, 0, 0, 0)
        self.port_range_container.setLayout(port_range_layout)
        
        self.port_scanner_start_port = QLineEdit("1")
        self.port_scanner_start_port.setMinimumHeight(30)
        port_range_layout.addWidget(self.port_scanner_start_port)
        
        port_range_layout.addWidget(QLabel("to"))
        
        self.port_scanner_end_port = QLineEdit("1024")
        self.port_scanner_end_port.setMinimumHeight(30)
        port_range_layout.addWidget(self.port_scanner_end_port)
        
        port_range_layout.addStretch()
        target_layout.addRow("Port Range:", self.port_range_container)
        
        self.port_scanner_speed = QComboBox()
        self.port_scanner_speed.addItems(["Slow (Stealthy)", "Normal", "Fast (Aggressive)"])
        self.port_scanner_speed.setCurrentIndex(1)
        self.port_scanner_speed.setMinimumHeight(30)
        target_layout.addRow("Scan Speed:", self.port_scanner_speed)
        
        self.port_scanner_service_detection = QCheckBox()
        self.port_scanner_service_detection.setChecked(True)
        target_layout.addRow("Detect Services:", self.port_scanner_service_detection)
        
        self.port_scanner_banner_grabbing = QCheckBox()
        self.port_scanner_banner_grabbing.setChecked(True)
        target_layout.addRow("Banner Grabbing:", self.port_scanner_banner_grabbing)
        
        self.port_scanner_firewall_detection = QCheckBox()
        self.port_scanner_firewall_detection.setChecked(True)
        target_layout.addRow("Firewall Detection:", self.port_scanner_firewall_detection)

        main_layout.addWidget(target_group)

        test_type_group = QGroupBox("Test Selection")
        test_type_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                border: 1px solid #5a5a5a;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #4CAF50;
            }
        """)
        
        test_type_layout = QVBoxLayout()
        test_type_layout.setSpacing(10)
        test_type_layout.setContentsMargins(15, 15, 15, 15)
        test_type_group.setLayout(test_type_layout)

        test_type_label = QLabel("Select Test Type:")
        test_type_label.setStyleSheet("font-weight: bold; color: #e0e0e0;")
        test_type_layout.addWidget(test_type_label)
        
        self.test_type_combo = QComboBox()
        self.test_type_combo.addItem("All Tests")
        self.test_type_combo.addItem("General Server Test")
        self.test_type_combo.addItem("Web Server Test")
        self.test_type_combo.addItem("Database Server Test")
        self.test_type_combo.addItem("Mail Server Test")
        self.test_type_combo.addItem("DNS Server Test")
        self.test_type_combo.addItem("File Server Test")
        self.test_type_combo.addItem("Stress/DDoS Test")
        self.test_type_combo.addItem("Port Scanner Test")
        self.test_type_combo.currentIndexChanged.connect(self.update_test_parameters)
        self.test_type_combo.setMinimumHeight(30)
        test_type_layout.addWidget(self.test_type_combo)

        main_layout.addWidget(test_type_group)

        # Create a hidden stacked widget to maintain compatibility with existing code
        self.param_stacked_widget = QStackedWidget()
        self.param_stacked_widget.setVisible(False)  # Hide it from the UI

        # We'll create empty placeholder widgets to maintain compatibility with existing code
        self.general_params_page = QWidget()
        self.web_params_page = QWidget()
        self.db_params_page = QWidget()
        self.mail_params_page = QWidget()
        self.dns_params_page = QWidget()
        self.file_params_page = QWidget()
        self.stress_ddos_params_page = QWidget()
        
        self.param_stacked_widget.addWidget(self.general_params_page)
        self.param_stacked_widget.addWidget(self.web_params_page)
        self.param_stacked_widget.addWidget(self.db_params_page)
        self.param_stacked_widget.addWidget(self.mail_params_page)
        self.param_stacked_widget.addWidget(self.dns_params_page)
        self.param_stacked_widget.addWidget(self.file_params_page)
        self.param_stacked_widget.addWidget(self.stress_ddos_params_page)
        
        # Database Server Test parameters
        self.db_user_input = QLineEdit()
        self.db_pass_input = QLineEdit()
        self.db_name_input = QLineEdit()
        
        self.mail_smtp_port_input = QLineEdit("25")
        self.mail_pop3_port_input = QLineEdit("110")
        
        self.dns_domain_input = QLineEdit("google.com")
        
        self.file_port_input = QLineEdit("22")
        self.file_user_input = QLineEdit()
        self.file_pass_input = QLineEdit()
        
        self.stress_ddos_port_input = QLineEdit("80")
        self.stress_ddos_attack_type = QComboBox()
        self.stress_ddos_attack_type.addItems(["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood", "All Attacks"])
        self.stress_ddos_threads_input = QLineEdit("2")
        self.stress_ddos_count_input = QLineEdit("100")
        self.stress_ddos_interval_input = QLineEdit("0.01")
        self.stress_ddos_http_method = QComboBox()
        self.stress_ddos_http_method.addItems(["GET", "POST"])
        self.stress_ddos_http_path = QLineEdit("/")
        self.stress_ddos_udp_size = QLineEdit("1024")
        self.stress_ddos_monitor_duration = QLineEdit("10")

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet("background-color: #5a5a5a;")
        main_layout.addWidget(separator)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.start_test_button = QPushButton("Start Test")
        self.start_test_button.setMinimumSize(150, 40)
        self.start_test_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        button_layout.addWidget(self.start_test_button)
        button_layout.addStretch()
        
        main_layout.addLayout(button_layout)

    def update_target_input(self, index):
        if index == 0: # IP Address
            self.target_input.setPlaceholderText("Enter IP Address")
        else: # Website Address
            self.target_input.setPlaceholderText("Enter Website URL (e.g., example.com or http://example.com)")

    def update_test_parameters(self, index):
        # Set the current widget based on the selected test type
        if index == 0: # All Tests
            self.param_stacked_widget.setCurrentIndex(0)
        elif index == 1: # General Server Test
            self.param_stacked_widget.setCurrentIndex(0)
        elif index == 2: # Web Server Test
            self.param_stacked_widget.setCurrentIndex(1)
        elif index == 3: # Database Server Test
            self.param_stacked_widget.setCurrentIndex(2)
        elif index == 4: # Mail Server Test
            self.param_stacked_widget.setCurrentIndex(3)
        elif index == 5: # DNS Server Test
            self.param_stacked_widget.setCurrentIndex(4)
        elif index == 6: # File Server Test
            self.param_stacked_widget.setCurrentIndex(5)
        elif index == 7: # Stress/DDoS Test
            self.param_stacked_widget.setCurrentIndex(6)
        elif index == 8: # Port Scanner Test
            self.param_stacked_widget.setCurrentIndex(0)
            
        if index == 8 and hasattr(self, 'port_scanner_mode'):
            self.update_port_scanner_mode(self.port_scanner_mode.currentIndex())
                
    def update_port_scanner_mode(self, index):
        if index == 0:  # Auto mode
            self.port_range_container.setVisible(False)
            self.port_scanner_start_port.setText("1")
            self.port_scanner_end_port.setText("1024")
        elif index == 1:  # Manual Range
            self.port_range_container.setVisible(True)
        elif index == 2:  # All Ports
            self.port_range_container.setVisible(False)
            self.port_scanner_start_port.setText("1")
            self.port_scanner_end_port.setText("65535")

    def get_test_parameters(self):
        params = {
            "target_type": self.target_type_combo.currentText(),
            "target": self.target_input.text(),
            "test_type": self.test_type_combo.currentText(),
            "general_port": self.general_port_input.text()  # Port is now always in Target Configuration
        }
        
        if params["test_type"] == "Database Server Test":
            params["db_user"] = self.db_user_input.text()
            params["db_pass"] = self.db_pass_input.text()
            params["db_name"] = self.db_name_input.text()
        elif params["test_type"] == "Mail Server Test":
            params["mail_smtp_port"] = self.mail_smtp_port_input.text()
            params["mail_pop3_port"] = self.mail_pop3_port_input.text()
        elif params["test_type"] == "DNS Server Test":
            params["dns_domain"] = self.dns_domain_input.text()
        elif params["test_type"] == "File Server Test":
            params["file_port"] = self.file_port_input.text()
            params["file_user"] = self.file_user_input.text()
            params["file_pass"] = self.file_pass_input.text()
        elif params["test_type"] == "Stress/DDoS Test":
            params["stress_ddos_port"] = self.stress_ddos_port_input.text()
            params["stress_ddos_count"] = self.stress_ddos_count_input.text()
            params["stress_ddos_interval"] = self.stress_ddos_interval_input.text()
            params["stress_ddos_threads"] = self.stress_ddos_threads_input.text()
            params["stress_ddos_attack_type"] = self.stress_ddos_attack_type.currentText()
            params["stress_ddos_http_method"] = self.stress_ddos_http_method.currentText()
            params["stress_ddos_http_path"] = self.stress_ddos_http_path.text()
            params["stress_ddos_udp_size"] = self.stress_ddos_udp_size.text()
            params["stress_ddos_monitor_duration"] = self.stress_ddos_monitor_duration.text()
        elif params["test_type"] == "Port Scanner Test":
            params["port_scanner_mode"] = self.port_scanner_mode.currentText()
            params["port_scanner_start_port"] = self.port_scanner_start_port.text()
            params["port_scanner_end_port"] = self.port_scanner_end_port.text()
            params["port_scanner_speed"] = self.port_scanner_speed.currentText()
            params["port_scanner_service_detection"] = self.port_scanner_service_detection.isChecked()
            params["port_scanner_banner_grabbing"] = self.port_scanner_banner_grabbing.isChecked()
            params["port_scanner_firewall_detection"] = self.port_scanner_firewall_detection.isChecked()

        return params