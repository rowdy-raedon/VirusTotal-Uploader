import sys
import os
import json
import time
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QTextEdit, QLineEdit, QMessageBox, QProgressBar,
                             QGroupBox, QSizePolicy, QDialog, QDialogButtonBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMimeData, QUrl
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QTextCharFormat, QTextCursor
import requests


class VirusTotalWorker(QThread):
    """Worker thread for VirusTotal API operations"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    progress_percent = pyqtSignal(int)
    
    def __init__(self, api_key, file_path, scan_type='upload'):
        super().__init__()
        self.api_key = api_key
        self.file_path = file_path
        self.scan_type = scan_type  # 'upload' or 'hash'
        self.file_hash = None
        
    def calculate_hash(self):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(self.file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def run(self):
        try:
            if self.scan_type == 'hash':
                # Try hash lookup first (faster)
                self.progress.emit("Calculating file hash...")
                self.file_hash = self.calculate_hash()
                self.progress.emit(f"Hash: {self.file_hash[:16]}...")
                self.progress.emit("Checking existing scan results...")
                
                report_url = f"https://www.virustotal.com/api/v3/files/{self.file_hash}"
                headers = {'x-apikey': self.api_key}
                response = requests.get(report_url, headers=headers)
                
                if response.status_code == 200:
                    self.progress.emit("Found existing scan results!")
                    report_data = response.json()
                    self.finished.emit({
                        'analysis': None,
                        'report': report_data,
                        'hash': self.file_hash
                    })
                    return
                elif response.status_code == 404:
                    self.progress.emit("No existing scan found. Uploading file...")
                    # Fall through to upload
                else:
                    self.progress.emit("Hash lookup failed. Uploading file...")
            
            # Upload file
            self.progress.emit("Uploading file to VirusTotal...")
            upload_url = "https://www.virustotal.com/api/v3/files"
            
            with open(self.file_path, 'rb') as f:
                files = {'file': (os.path.basename(self.file_path), f)}
                headers = {'x-apikey': self.api_key}
                response = requests.post(upload_url, files=files, headers=headers, timeout=300)
                
            if response.status_code == 200:
                upload_data = response.json()
                file_id = upload_data['data']['id']
                self.progress.emit(f"✓ Uploaded. Analyzing...")
                
                # Get analysis results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
                headers = {'x-apikey': self.api_key}
                
                # Poll for results
                max_attempts = 40
                for attempt in range(max_attempts):
                    progress = int((attempt / max_attempts) * 80) + 10
                    self.progress_percent.emit(progress)
                    
                    time.sleep(2)
                    response = requests.get(analysis_url, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        analysis_data = response.json()
                        status = analysis_data['data']['attributes']['status']
                        
                        if status == 'completed':
                            self.progress_percent.emit(90)
                            self.progress.emit("✓ Analysis complete! Fetching report...")
                            # Get detailed report
                            report_url = f"https://www.virustotal.com/api/v3/files/{file_id}"
                            report_response = requests.get(report_url, headers=headers, timeout=30)
                            
                            if report_response.status_code == 200:
                                report_data = report_response.json()
                                self.progress_percent.emit(100)
                                self.finished.emit({
                                    'analysis': analysis_data,
                                    'report': report_data,
                                    'hash': file_id
                                })
                            else:
                                self.finished.emit({
                                    'analysis': analysis_data,
                                    'report': None,
                                    'hash': file_id
                                })
                            return
                        elif status == 'queued':
                            self.progress.emit(f"⏳ Queued... ({attempt + 1}/{max_attempts})")
                        else:
                            self.progress.emit(f"⏳ Processing... ({attempt + 1}/{max_attempts})")
                    else:
                        self.progress.emit(f"⏳ Checking... ({attempt + 1}/{max_attempts})")
                
                self.error.emit("Timeout: Analysis took too long (>80s)")
            else:
                error_text = response.text
                if response.status_code == 401:
                    self.error.emit("Invalid API key. Please check your settings.")
                elif response.status_code == 429:
                    self.error.emit("Rate limit exceeded. Please wait a moment.")
                elif response.status_code == 413:
                    self.error.emit("File too large. Maximum size is 32MB (free API).")
                else:
                    self.error.emit(f"Upload failed ({response.status_code}): {error_text[:100]}")
            
        except FileNotFoundError:
            self.error.emit(f"File not found: {self.file_path}")
        except requests.exceptions.Timeout:
            self.error.emit("Request timeout. Check your internet connection.")
        except requests.exceptions.RequestException as e:
            self.error.emit(f"Network error: {str(e)}")
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")


class SettingsDialog(QDialog):
    """Settings dialog for API key configuration"""
    def __init__(self, parent=None, api_key=""):
        super().__init__(parent)
        self.api_key = api_key
        self.init_ui()
        self.apply_dark_theme()
    
    def init_ui(self):
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(450)
        self.setMaximumHeight(300)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(18, 18, 18, 18)
        
        title = QLabel("⚙️ Settings")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet("color: #00D4FF; padding-bottom: 8px;")
        layout.addWidget(title)
        
        api_key_layout = QVBoxLayout()
        api_key_label = QLabel("API Key:")
        api_key_label.setStyleSheet("color: #B0B0B0; font-weight: bold; font-size: 10pt;")
        api_key_layout.addWidget(api_key_label)
        
        api_input_layout = QHBoxLayout()
        self.api_key_input = QLineEdit()
        self.api_key_input.setText(self.api_key)
        self.api_key_input.setPlaceholderText("Enter your VirusTotal API key")
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setStyleSheet("""
            QLineEdit {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 7px;
                color: #E0E0E0;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 1px solid #00D4FF;
            }
        """)
        
        self.toggle_api_btn = QPushButton("👁")
        self.toggle_api_btn.setMaximumWidth(38)
        self.toggle_api_btn.setToolTip("Show/Hide")
        self.toggle_api_btn.clicked.connect(self.toggle_api_visibility)
        self.toggle_api_btn.setStyleSheet("""
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 4px;
                color: #B0B0B0;
            }
            QPushButton:hover {
                background-color: #353535;
                border: 1px solid #00D4FF;
            }
        """)
        
        api_input_layout.addWidget(self.api_key_input)
        api_input_layout.addWidget(self.toggle_api_btn)
        api_key_layout.addLayout(api_input_layout)
        
        api_info = QLabel("Get key: <a href='https://www.virustotal.com/gui/join-us' style='color: #00D4FF;'>virustotal.com</a>")
        api_info.setOpenExternalLinks(True)
        api_info.setStyleSheet("color: #888; font-size: 8pt; padding-top: 3px;")
        api_key_layout.addWidget(api_info)
        
        layout.addLayout(api_key_layout)
        layout.addStretch()
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.setStyleSheet("""
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 7px 18px;
                color: #E0E0E0;
                min-width: 75px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: #353535;
                border: 1px solid #00D4FF;
            }
            QPushButton#okButton {
                background-color: #00D4FF;
                color: #1A1A1A;
                font-weight: bold;
            }
            QPushButton#okButton:hover {
                background-color: #00B8E6;
            }
        """)
        layout.addWidget(button_box)
    
    def apply_dark_theme(self):
        self.setStyleSheet("QDialog { background-color: #1A1A1A; }")
    
    def toggle_api_visibility(self):
        if self.api_key_input.echoMode() == QLineEdit.Password:
            self.api_key_input.setEchoMode(QLineEdit.Normal)
            self.toggle_api_btn.setText("🙈")
        else:
            self.api_key_input.setEchoMode(QLineEdit.Password)
            self.toggle_api_btn.setText("👁")
    
    def get_api_key(self):
        return self.api_key_input.text().strip()


class VirusTotalChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api_key = ""
        self.selected_file = ""
        self.worker = None
        self.init_ui()
        self.load_config()
        self.setAcceptDrops(True)
        
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files and os.path.isfile(files[0]):
            self.selected_file = files[0]
            self.update_file_display()
            self.update_button_states()
    
    def init_ui(self):
        self.setWindowTitle("VirusTotal Checker")
        self.setGeometry(100, 100, 600, 550)
        
        self.apply_dark_theme()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Compact header
        header_layout = QHBoxLayout()
        title = QLabel("🛡️ VirusTotal")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet("color: #00D4FF;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.api_status_label = QLabel("⚙️ No API key")
        self.api_status_label.setStyleSheet("color: #888; font-size: 8pt; padding: 2px 6px;")
        header_layout.addWidget(self.api_status_label)
        
        self.settings_btn = QPushButton("⚙️")
        self.settings_btn.setMaximumWidth(32)
        self.settings_btn.setMaximumHeight(28)
        self.settings_btn.setToolTip("Settings")
        self.settings_btn.clicked.connect(self.open_settings)
        self.settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 3px;
                color: #B0B0B0;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #353535;
                border: 1px solid #00D4FF;
            }
        """)
        header_layout.addWidget(self.settings_btn)
        layout.addLayout(header_layout)
        
        # File selection (compact)
        file_layout = QHBoxLayout()
        self.select_file_btn = QPushButton("📁")
        self.select_file_btn.setMaximumWidth(40)
        self.select_file_btn.setToolTip("Select File")
        self.select_file_btn.clicked.connect(self.select_file)
        self.select_file_btn.setStyleSheet("""
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 3px;
                padding: 6px;
                color: #E0E0E0;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #353535;
                border: 1px solid #00D4FF;
            }
        """)
        
        self.selected_file_label = QLabel("Drop file here or click 📁")
        self.selected_file_label.setStyleSheet("color: #888; padding: 4px; font-size: 9pt;")
        self.selected_file_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.selected_file_label.setWordWrap(True)
        
        file_layout.addWidget(self.select_file_btn)
        file_layout.addWidget(self.selected_file_label)
        layout.addLayout(file_layout)
        
        # Upload button
        self.upload_btn = QPushButton("🚀 Scan File")
        self.upload_btn.setMinimumHeight(36)
        self.upload_btn.setStyleSheet("""
            QPushButton {
                background-color: #00D4FF;
                color: #1A1A1A;
                font-size: 11pt;
                font-weight: bold;
                border-radius: 4px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #00B8E6;
            }
            QPushButton:disabled {
                background-color: #2A2A2A;
                color: #666;
                border: 1px solid #404040;
            }
        """)
        self.upload_btn.clicked.connect(self.upload_file)
        self.upload_btn.setEnabled(False)
        layout.addWidget(self.upload_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(20)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #404040;
                border-radius: 3px;
                text-align: center;
                color: #E0E0E0;
                background-color: #2A2A2A;
                font-size: 8pt;
            }
            QProgressBar::chunk {
                background-color: #00D4FF;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Compact status
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #B0B0B0; font-size: 8pt; padding: 2px; min-height: 16px;")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        # Results
        results_header = QHBoxLayout()
        results_title = QLabel("Results:")
        results_title.setStyleSheet("color: #B0B0B0; font-weight: bold; font-size: 9pt;")
        results_header.addWidget(results_title)
        results_header.addStretch()
        
        self.copy_btn = QPushButton("📋 Copy")
        self.copy_btn.setMaximumWidth(50)
        self.copy_btn.setMaximumHeight(22)
        self.copy_btn.setToolTip("Copy results")
        self.copy_btn.clicked.connect(self.copy_results)
        self.copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #2A2A2A;
                border: 1px solid #404040;
                border-radius: 3px;
                padding: 2px 6px;
                color: #B0B0B0;
                font-size: 8pt;
            }
            QPushButton:hover {
                background-color: #353535;
                border: 1px solid #00D4FF;
            }
        """)
        results_header.addWidget(self.copy_btn)
        layout.addLayout(results_header)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("Scan results will appear here...")
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                border: 1px solid #404040;
                border-radius: 4px;
                color: #E0E0E0;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 8.5pt;
                padding: 6px;
            }
        """)
        layout.addWidget(self.results_text, 1)
        
        self.update_button_states()
    
    def apply_dark_theme(self):
        dark_stylesheet = """
            QMainWindow { background-color: #1A1A1A; }
            QWidget { background-color: #1A1A1A; color: #E0E0E0; }
        """
        self.setStyleSheet(dark_stylesheet)
        
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(26, 26, 26))
        palette.setColor(QPalette.WindowText, QColor(224, 224, 224))
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.Text, QColor(224, 224, 224))
        palette.setColor(QPalette.Button, QColor(42, 42, 42))
        palette.setColor(QPalette.ButtonText, QColor(224, 224, 224))
        palette.setColor(QPalette.Highlight, QColor(0, 212, 255))
        self.setPalette(palette)
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def update_file_display(self):
        if self.selected_file:
            file_name = os.path.basename(self.selected_file)
            file_size = os.path.getsize(self.selected_file)
            size_str = self.format_file_size(file_size)
            self.selected_file_label.setText(f"{file_name} ({size_str})")
        else:
            self.selected_file_label.setText("Drop file here or click 📁")
    
    def load_config(self):
        config_file = "config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key', '')
                    self.update_api_status()
                    self.update_button_states()
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def save_config(self):
        config_file = "config.json"
        try:
            with open(config_file, 'w') as f:
                json.dump({'api_key': self.api_key}, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def update_api_status(self):
        if self.api_key:
            masked_key = f"{self.api_key[:6]}...{self.api_key[-4:]}" if len(self.api_key) > 10 else "***"
            self.api_status_label.setText(f"✓ {masked_key}")
            self.api_status_label.setStyleSheet("color: #4CAF50; font-size: 8pt; padding: 2px 6px;")
        else:
            self.api_status_label.setText("⚙️ No API key")
            self.api_status_label.setStyleSheet("color: #888; font-size: 8pt; padding: 2px 6px;")
    
    def open_settings(self):
        dialog = SettingsDialog(self, self.api_key)
        if dialog.exec_() == QDialog.Accepted:
            new_api_key = dialog.get_api_key()
            if new_api_key != self.api_key:
                self.api_key = new_api_key
                self.save_config()
                self.update_api_status()
                self.update_button_states()
                self.update_status("✓ API key updated", "#4CAF50")
    
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*.*)"
        )
        if file_path:
            self.selected_file = file_path
            self.update_file_display()
            self.update_button_states()
    
    def update_button_states(self):
        self.upload_btn.setEnabled(bool(self.api_key) and bool(self.selected_file))
    
    def update_status(self, message, color="#B0B0B0"):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 8pt; padding: 2px; min-height: 16px;")
        QApplication.processEvents()
    
    def upload_file(self):
        if not self.api_key:
            QMessageBox.warning(self, "API Key Required", 
                              "Configure API key in Settings (⚙️)")
            return
        
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a file")
            return
        
        file_size = os.path.getsize(self.selected_file)
        if file_size > 32 * 1024 * 1024:
            reply = QMessageBox.warning(
                self, "File Size Warning",
                f"File ({self.format_file_size(file_size)}) exceeds 32MB limit.\nContinue?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        self.upload_btn.setEnabled(False)
        self.select_file_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        self.update_status("Starting scan...", "#00D4FF")
        
        # Try hash lookup first, then upload if needed
        self.worker = VirusTotalWorker(self.api_key, self.selected_file, scan_type='hash')
        self.worker.progress.connect(self.update_status)
        self.worker.progress_percent.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_scan_complete)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()
    
    def on_scan_complete(self, data):
        self.progress_bar.setVisible(False)
        self.upload_btn.setEnabled(True)
        self.select_file_btn.setEnabled(True)
        
        analysis = data.get('analysis', {})
        report = data.get('report', {})
        
        if report:
            attributes = report.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            
            # Format results
            results = "═" * 65 + "\n"
            results += "🛡️  VIRUSTOTAL SCAN RESULTS\n"
            results += "═" * 65 + "\n\n"
            
            results += f"📄 File: {os.path.basename(self.selected_file)}\n"
            results += f"🔐 SHA256: {attributes.get('sha256', 'N/A')[:32]}...\n"
            results += f"🔐 MD5:    {attributes.get('md5', 'N/A')}\n\n"
            
            results += "📊 Statistics:\n"
            results += f"   ✓ Harmless:   {harmless}/{total}\n"
            results += f"   ✗ Malicious:  {malicious}/{total}\n"
            results += f"   ⚠ Suspicious: {suspicious}/{total}\n"
            results += f"   ? Undetected: {undetected}/{total}\n\n"
            
            # Threat detections
            last_analysis_results = attributes.get('last_analysis_results', {})
            if last_analysis_results:
                threats = []
                for engine, result in last_analysis_results.items():
                    category = result.get('category', '')
                    if category in ['malicious', 'suspicious']:
                        result_text = result.get('result', 'N/A')
                        threats.append(f"  • {engine}: {result_text}")
                
                if threats:
                    results += "🔍 Threats Detected:\n"
                    results += "─" * 65 + "\n"
                    results += "\n".join(threats[:10])  # Limit to 10
                    if len(threats) > 10:
                        results += f"\n  ... and {len(threats) - 10} more\n"
                else:
                    results += "✓ No threats detected\n"
            
            results += "\n" + "═" * 65 + "\n"
            if malicious > 0:
                results += f"⚠️  WARNING: {malicious} engine(s) flagged as MALICIOUS\n"
                verdict_color = "#FF4444"
            elif suspicious > 0:
                results += f"⚠️  CAUTION: {suspicious} engine(s) flagged as SUSPICIOUS\n"
                verdict_color = "#FFAA00"
            else:
                results += "✅ VERDICT: No threats detected\n"
                verdict_color = "#4CAF50"
            
            self.results_text.setPlainText(results)
            self.update_status("✓ Scan complete!", verdict_color)
        else:
            self.results_text.setPlainText("⚠️ Report data unavailable")
            self.update_status("⚠️ Partial results", "#FFAA00")
    
    def on_scan_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.upload_btn.setEnabled(True)
        self.select_file_btn.setEnabled(True)
        self.update_status(f"✗ Error: {error_message}", "#FF4444")
        QMessageBox.critical(self, "Scan Error", error_message)
    
    def copy_results(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.results_text.toPlainText())
        self.update_status("✓ Results copied to clipboard", "#4CAF50")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("VirusTotal Checker")
    
    window = VirusTotalChecker()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
