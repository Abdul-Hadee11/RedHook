import sys
import os
from PyQt5.QtWidgets import (
    QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QLineEdit,
    QApplication
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QTimer
from core.gmail_fetcher import fetch_recent_emails
from core.core_redhook import analyze_email
from core.db_manager import fetch_all_analyses, save_analysis, delete_all_emails, delete_email_by_id
from core.url_checker import scan_urls
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))



class RedHookApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RedHook – Email Phishing Detection Suite")
        self.setGeometry(100, 100, 1200, 740)
        self.center_window()

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #f5f5f5;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #e50914;
                color: white;
                font-weight: bold;
                padding: 6px;
                border: 1px solid #111;
            }
            QTableWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                gridline-color: #333;
                selection-background-color: #0078d7;
            }
            QTableWidget::item:selected {
                color: white;
            }
            QTextEdit, QLineEdit {
                background-color: #000;
                color: #00FF00;
                font-family: Consolas, monospace;
                font-size: 14px;
                padding: 8px;
            }
            QPushButton {
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
                background-color: #e50914;
                color: white;
            }
            QPushButton:hover {
                background-color: #c40812;
            }
            QTabBar::tab {
                height: 40px;
                width: 160px;
                font-weight: bold;
                font-size: 14px;
                color: white;
                background: #1c1c1c;
                border: 1px solid #444;
                border-bottom: none;
                padding: 10px;
            }
            QTabBar::tab:selected {
                background-color: #e50914;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                top: -1px;
            }
        """)

        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        self.tabs = QTabWidget()
        self.email_analysis_tab = QWidget()
        self.email_history_tab = QWidget()
        self.url_scanner_tab = QWidget()
        self.about_tab = QWidget()
        self.tabs.addTab(self.email_analysis_tab, "📊 Email Analysis")
        self.tabs.addTab(self.email_history_tab, "📜 Email History")
        self.tabs.addTab(self.url_scanner_tab, "🔗 URL Scanner")
        self.tabs.addTab(self.about_tab, "ℹ️ About")
        main_layout.addWidget(self.tabs)

        self.logo_label = QLabel(self)
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        pixmap = QPixmap(logo_path)
        if not pixmap.isNull():
            self.logo_label.setPixmap(pixmap.scaled(250, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.logo_label.setStyleSheet("background: transparent;")
        self.logo_label.setFixedSize(250, 100)
        self.logo_label.move(self.width() - 300, -5)
        self.logo_label.raise_()
        self.resizeEvent = self.on_resize

        self.init_email_analysis_tab()
        self.init_email_history_tab()
        self.init_url_scanner_tab()
        self.init_about_tab()

    def center_window(self):
        frame_geometry = self.frameGeometry()
        screen = QApplication.primaryScreen().availableGeometry().center()
        frame_geometry.moveCenter(screen)
        self.move(frame_geometry.topLeft())

    def on_resize(self, event):
        self.logo_label.move(self.width() - 300, -5)

    def init_email_analysis_tab(self):
        layout = QVBoxLayout()

        self.fetch_button = QPushButton("📩 Fetch Emails from Gmail")
        self.fetch_button.clicked.connect(self.fetch_emails)

        self.email_table = QTableWidget()
        self.email_table.setColumnCount(3)
        self.email_table.setHorizontalHeaderLabels(["Subject", "Sender", "Date"])
        self.email_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.email_table.cellClicked.connect(self.display_email_details)

        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setText("🧪 Click on Fetch Email.")

        output_header_layout = QHBoxLayout()
        output_label = QLabel("📄 Email Analysis Output:")
        self.clear_button = QPushButton("🧹 Clear Details")
        self.clear_button.setFixedWidth(150)
        self.clear_button.clicked.connect(self.clear_analysis_output)
        output_header_layout.addWidget(output_label)
        output_header_layout.addStretch()
        output_header_layout.addWidget(self.clear_button)

        layout.addWidget(self.fetch_button)
        layout.addWidget(self.email_table)
        layout.addLayout(output_header_layout)
        layout.addWidget(self.analysis_output)

        self.email_analysis_tab.setLayout(layout)

    def clear_analysis_output(self):
        self.analysis_output.clear()

    def fetch_emails(self):
        self.analysis_output.setText("📩 Fetching emails, please wait...")
        QApplication.processEvents()
        QTimer.singleShot(100, self._perform_fetch)

    def _perform_fetch(self):
        self.analysis_output.clear()
        self.email_table.setRowCount(0)
        try:
            self.emails = fetch_recent_emails(5)
            if not self.emails:
                self.analysis_output.setPlainText("⚠️ No new emails found.")
                return
            self.email_table.setRowCount(len(self.emails))
            for row, mail in enumerate(self.emails):
                subject = mail.get("subject", "No Subject")
                sender = mail.get("from", "Unknown Sender")
                date = mail.get("timestamp", "N/A")
                self.email_table.setItem(row, 0, QTableWidgetItem(subject))
                self.email_table.setItem(row, 1, QTableWidgetItem(sender))
                self.email_table.setItem(row, 2, QTableWidgetItem(date))
            self.analysis_output.setPlainText("✅ Emails fetched successfully.\n\n📥 Click on any email to analyze it.")
        except Exception as e:
            self.analysis_output.setPlainText(f"❌ Error while fetching emails:\n{str(e)}")

    def display_email_details(self, row, _):
        try:
            self.analysis_output.setText("🔄 Analyzing email, please wait...")
            QApplication.processEvents()
            selected_email = self.emails[row]
            subject = selected_email.get("subject", "")
            sender = selected_email.get("from", "")
            body = selected_email.get("body", "")
            date = selected_email.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M"))
            verdict, tactics, urls, explanation = analyze_email(body, full_details=True)
            save_analysis(subject, sender, date, verdict, tactics, urls, explanation)

            output = f"""
📌 Subject: {subject}
👤 Sender: {sender}
📅 Date: {date}
🔍 Verdict: {verdict.upper()}
🎯 Tactics: {', '.join(tactics) if tactics else 'None'}
🔗 URLs: {', '.join(urls) if urls else 'None'}

📝 Explanation:
{explanation}
            """.strip()

            self.analysis_output.setPlainText(output)
            self.load_email_history()
        except Exception as e:
            self.analysis_output.setPlainText(f"❌ Error analyzing email:\n{str(e)}")

    def init_email_history_tab(self):
        layout = QVBoxLayout()
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Subject", "Sender", "Date", "Verdict"])
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)

        button_row = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh History")
        self.refresh_btn.clicked.connect(self.load_email_history)

        self.delete_selected_btn = QPushButton("❌ Delete Selected")
        self.delete_selected_btn.clicked.connect(self.delete_selected_history)

        self.clear_all_btn = QPushButton("🗑️ Clear All History")
        self.clear_all_btn.clicked.connect(self.clear_all_history)

        button_row.addWidget(self.refresh_btn)
        button_row.addStretch()
        button_row.addWidget(self.delete_selected_btn)
        button_row.addWidget(self.clear_all_btn)

        layout.addLayout(button_row)
        layout.addWidget(self.history_table)
        self.email_history_tab.setLayout(layout)
        self.load_email_history()

    def load_email_history(self):
        try:
            records = fetch_all_analyses()
            self.history_table.setRowCount(len(records))
            for row, record in enumerate(records):
                subject = record[1]
                sender = record[2]
                date = record[3]
                verdict = record[4]
                self.history_table.setItem(row, 0, QTableWidgetItem(subject))
                self.history_table.setItem(row, 1, QTableWidgetItem(sender))
                self.history_table.setItem(row, 2, QTableWidgetItem(date))
                self.history_table.setItem(row, 3, QTableWidgetItem(verdict))
        except Exception as e:
            print(f"❌ Error loading history: {e}")

    def delete_selected_history(self):
        selected_row = self.history_table.currentRow()
        if selected_row == -1:
            print("⚠️ No row selected.")
            return
        subject = self.history_table.item(selected_row, 0).text()
        sender = self.history_table.item(selected_row, 1).text()
        date = self.history_table.item(selected_row, 2).text()

        records = fetch_all_analyses()
        for record in records:
            if record[1] == subject and record[2] == sender and record[3] == date:
                delete_email_by_id(record[0])
                break
        self.load_email_history()

    def clear_all_history(self):
        delete_all_emails()
        self.load_email_history()

    def init_url_scanner_tab(self):
        layout = QVBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("🔗 Enter URL to scan...")

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("🚨 Scan URL")
        self.scan_button.clicked.connect(self.scan_url)

        self.clear_button = QPushButton("🧹 Clear")
        self.clear_button.clicked.connect(lambda: self.scan_result.clear())

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.clear_button)

        self.scan_result = QTextEdit()
        self.scan_result.setReadOnly(True)

        layout.addWidget(self.url_input)
        layout.addLayout(button_layout)
        layout.addWidget(QLabel("🧪 URL Scan Result:"))
        layout.addWidget(self.scan_result)
        self.url_scanner_tab.setLayout(layout)


    def scan_url(self):
        url = self.url_input.text().strip()
        if not url:
            self.scan_result.setHtml("<font color='orange'>❌ Please enter a valid URL.</font>")
            return
        try:
            results = scan_urls(url)
            output = []
            for res in results:
                line = f"""
                    🔗 <b>URL</b>: {res['url']}<br>
                    🛡️ <b>VirusTotal</b>: {res['vt_result']}<br>
                    🧠 <b>Features</b>:<br>
                            • URL Length: {res['features'][0]}<br>
                            • Has IP: {'Yes' if res['features'][1] else 'No'}<br>
                            • Num Subdomains: {res['features'][2]}<br>
                            • Suspicious TLD: {'Yes' if res['features'][3] else 'No'}<br>
                            • Uses HTTPS: {'Yes' if res['features'][4] else 'No'}<br>
                            • Has Login Keyword: {'Yes' if res['features'][5] else 'No'}<br>
                            • Payload Query Present: {'Yes' if res['features'][6] else 'No'}<br>
                            • Num Dashes: {res['features'][7]}<br>
                            • Is Shortened: {'Yes' if res['features'][8] else 'No'}<br>

                    <hr>
                """
                output.append(line)
            self.scan_result.setHtml("<br>".join(output))
        except Exception as e:
            self.scan_result.setHtml(f"<font color='red'>❌ Error scanning URL:<br>{str(e)}</font>")



    def init_about_tab(self):
        layout = QVBoxLayout()

        # RedHook Logo
        
        # RedHook Title
        title = QLabel("🔴 RedHook – Email Phishing Detection Suite")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)

        # Description
        desc = QLabel(
            "RedHook is an advanced cybersecurity tool designed to detect phishing emails and\n"
            "malicious URLs using machine learning, heuristic analysis, and VirusTotal integration.\n"
            "It helps individuals and organizations stay protected against social engineering attacks."
        )
        desc.setStyleSheet("margin-top: 10px; font-size: 13px;")
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)

        # Credits
        credits = QLabel("👨‍💻 Made with ❤️ by Abdul Hadee")
        credits.setAlignment(Qt.AlignCenter)
        credits.setStyleSheet("margin-top: 15px; font-size: 12px; color: #aaaaaa;")

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addWidget(credits)

        self.about_tab.setLayout(layout)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RedHookApp()
    window.show()
    sys.exit(app.exec_())
