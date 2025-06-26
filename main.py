import sys
import os
import logging
import threading
import socket
import requests
import time
import json 
import subprocess 

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox, QDialog, QFormLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt, QEvent, QObject 
from PyQt5.QtGui import QFont, QTextCursor

from server_thread import FlaskServerThread
from config_manager import ConfigManager
from queue import Queue, Empty 

# --- Custom Logging Handler for GUI ---
class QTextEditLogger(logging.Handler, QObject): 
    """
    A custom logging handler that emits a PyQt signal when a log record is received.
    This signal carries the formatted log message and its level.
    """
    append_text = pyqtSignal(str, int) # message, log_level

    def __init__(self, parent=None): 
        logging.Handler.__init__(self) 
        QObject.__init__(self, parent) 
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    def emit(self, record):
        """Emit a log record. This method is called by the logging system."""
        msg = self.format(record)
        self.append_text.emit(msg, record.levelno)

# Configure logging for the main application
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO) 

console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__) 

class MessageProcessor(QThread):
    """
    A QThread to process messages from the Flask server thread
    and emit signals to update the GUI.
    This prevents direct GUI updates from non-GUI threads.
    """
    update_webhook_status_signal = pyqtSignal(int, str, str, str) 
    server_error_signal = pyqtSignal(str)
    server_startup_info_signal = pyqtSignal(str, int, str, str) 

    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self._running = True

    def run(self):
        while self._running:
            try:
                message_type, *args = self.queue.get(timeout=0.1) 
                if message_type == 'update_webhook_status':
                    webhook_id, status, timestamp, logs = args
                    self.update_webhook_status_signal.emit(webhook_id, status, timestamp, logs)
                elif message_type == 'server_error':
                    error_message = args[0]
                    self.server_error_signal.emit(error_message)
                elif message_type == 'server_startup_info':
                    local_ip, port, public_ip, base_url = args
                    self.server_startup_info_signal.emit(local_ip, port, public_ip, base_url)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing message from queue: {e}")
                time.sleep(0.1) 

    def stop(self):
        self._running = False
        self.wait() 

class CICDApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        self.webhook_server_thread = None
        self.server_message_queue = Queue() 
        
        self.log_handler = QTextEditLogger(self) 
        self.log_handler.append_text.connect(self._append_to_server_log_slot) 
        root_logger.addHandler(self.log_handler) 

        self.message_processor = MessageProcessor(self.server_message_queue)
        self.message_processor.update_webhook_status_signal.connect(self.update_webhook_status_in_table)
        self.message_processor.server_error_signal.connect(self.show_server_error)
        self.message_processor.server_startup_info_signal.connect(self.update_server_status_display)
        self.message_processor.start()

        self.init_ui()
        self.load_webhooks()
        self.load_settings()

    def init_ui(self):
        self.setWindowTitle("CI/CD Webhook Desktop Server")
        self.setGeometry(100, 100, 1200, 800) 

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        # Webhooks Tab
        self.webhooks_tab = QWidget()
        self.tab_widget.addTab(self.webhooks_tab, "Webhooks")
        self.init_webhooks_tab()

        # Server Status Tab
        self.server_status_tab = QWidget()
        self.tab_widget.addTab(self.server_status_tab, "Server Status")
        self.init_server_status_tab()

        # Settings Tab
        self.settings_tab = QWidget()
        self.tab_widget.addTab(self.settings_tab, "Settings")
        self.init_settings_tab()

        self.current_webhook_id = None 

    def init_webhooks_tab(self):
        layout = QVBoxLayout(self.webhooks_tab)

        # Notification label
        self.notification_label = QLabel("")
        self.notification_label.setStyleSheet("color: green; font-weight: bold;")
        self.notification_label.setVisible(False)
        layout.addWidget(self.notification_label)

        # Add/Edit Webhook Form
        form_group = QWidget()
        form_layout = QVBoxLayout(form_group)
        
        self.form_title = QLabel("Add New Webhook")
        self.form_title.setFont(QFont("Arial", 16, QFont.Bold))
        form_layout.addWidget(self.form_title)

        form_fields_layout = QFormLayout()
        self.webhook_name_input = QLineEdit()
        self.webhook_name_input.setPlaceholderText("e.g., bitbucket-prod-deploy")
        form_fields_layout.addRow("Webhook Name:", self.webhook_name_input)

        self.webhook_commands_input = QTextEdit()
        self.webhook_commands_input.setPlaceholderText("e.g.,\ncd /path/to/your/app\ngit pull origin main\n./deploy-script.sh")
        self.webhook_commands_input.setMinimumHeight(120)
        form_fields_layout.addRow("Deployment Commands (Shell Script):", self.webhook_commands_input)

        self.webhook_email_input = QLineEdit()
        self.webhook_email_input.setPlaceholderText("e.g., your_email@example.com")
        form_fields_layout.addRow("Email for Notifications (Optional):", self.webhook_email_input)
        form_layout.addLayout(form_fields_layout)

        button_layout = QHBoxLayout()
        self.submit_button = QPushButton("Add Webhook")
        self.submit_button.clicked.connect(self.add_update_webhook)
        button_layout.addWidget(self.submit_button)

        self.cancel_edit_button = QPushButton("Cancel Edit")
        self.cancel_edit_button.clicked.connect(self.clear_form)
        self.cancel_edit_button.setVisible(False)
        button_layout.addWidget(self.cancel_edit_button)

        self.test_script_button = QPushButton("Test Commands")
        self.test_script_button.clicked.connect(self.test_commands)
        button_layout.addWidget(self.test_script_button)
        form_layout.addLayout(button_layout)

        self.test_script_output_label = QLabel("Test Script Output:")
        self.test_script_output_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.test_script_output_label.setVisible(False)
        form_layout.addWidget(self.test_script_output_label)

        self.test_script_logs = QTextEdit()
        self.test_script_logs.setReadOnly(True)
        self.test_script_logs.setFont(QFont("Monospace", 9))
        self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #48bb78; border-radius: 5px; padding: 5px;")
        self.test_script_logs.setVisible(False)
        form_layout.addWidget(self.test_script_logs)

        self.test_script_status_label = QLabel("")
        self.test_script_status_label.setFont(QFont("Arial", 10))
        self.test_script_status_label.setVisible(False)
        form_layout.addWidget(self.test_script_status_label)
        
        layout.addWidget(form_group)

        # Webhook List
        self.webhook_list_label = QLabel("Configured Webhooks")
        self.webhook_list_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(self.webhook_list_label)

        self.webhook_table = QTableWidget()
        self.webhook_table.setColumnCount(8) 
        self.webhook_table.setHorizontalHeaderLabels(["ID", "Name", "Commands", "Email", "Trigger URL", "Status", "Last Run", "Actions"])
        self.webhook_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) 
        self.webhook_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents) 
        self.webhook_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents) 
        self.webhook_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents) 
        self.webhook_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.webhook_table.setSelectionMode(QAbstractItemView.NoSelection) 
        layout.addWidget(self.webhook_table)

    def init_server_status_tab(self):
        layout = QVBoxLayout(self.server_status_tab)

        # Server Controls
        control_group = QWidget()
        control_layout = QHBoxLayout(control_group)
        self.start_server_button = QPushButton("Start Server")
        self.start_server_button.clicked.connect(self.start_server)
        control_layout.addWidget(self.start_server_button)

        self.stop_server_button = QPushButton("Stop Server")
        self.stop_server_button.clicked.connect(self.stop_server)
        self.stop_server_button.setEnabled(False) 
        control_layout.addWidget(self.stop_server_button)
        layout.addWidget(control_group)

        # Server Info Display
        info_group = QWidget()
        info_layout = QFormLayout(info_group)
        
        self.server_status_label = QLabel("Status: Stopped")
        self.server_status_label.setStyleSheet("font-weight: bold; color: red;")
        info_layout.addRow("Server Status:", self.server_status_label)

        self.local_ip_label = QLabel("Local IP: N/A")
        info_layout.addRow("Local IP Address:", self.local_ip_label)

        self.public_ip_label = QLabel("Public IP: N/A")
        info_layout.addRow("Public IP Address:", self.public_ip_label)

        self.server_port_label = QLabel("Port: N/A")
        info_layout.addRow("Listening Port:", self.server_port_label)

        self.base_trigger_url_label = QLabel("Base Trigger URL: N/A")
        info_layout.addRow("Base Trigger URL:", self.base_trigger_url_label)

        layout.addWidget(info_group)

        # Server Log Display
        self.server_log_label = QLabel("Server Activity Log:")
        self.server_log_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(self.server_log_label)

        self.server_log_output = QTextEdit()
        self.server_log_output.setReadOnly(True)
        self.server_log_output.setFont(QFont("Monospace", 9))
        self.server_log_output.setStyleSheet("background-color: #f0f0f0; color: #333; border-radius: 5px; padding: 5px;")
        layout.addWidget(self.server_log_output)
        

    def _append_to_server_log_slot(self, text, levelno):
        """
        Slot to receive log messages from the QTextEditLogger and append them to the QTextEdit.
        Colors based on log level.
        """
        cursor = self.server_log_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        color = "black"
        if levelno >= logging.CRITICAL:
            color = "red"
        elif levelno >= logging.ERROR:
            color = "red"
        elif levelno >= logging.WARNING:
            color = "orange"
        elif levelno >= logging.INFO:
            color = "green" 
        elif levelno >= logging.DEBUG:
            color = "gray"
        
        cursor.insertHtml(f"<span style='color: {color};'>{text}</span><br>")
        self.server_log_output.setTextCursor(cursor)
        self.server_log_output.verticalScrollBar().setValue(self.server_log_output.verticalScrollBar().maximum())


    def init_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)

        settings_form_group = QWidget()
        settings_form_layout = QFormLayout(settings_form_group)

        self.smtp_server_input = QLineEdit()
        settings_form_layout.addRow("SMTP Server:", self.smtp_server_input)

        self.smtp_port_input = QLineEdit()
        self.smtp_port_input.setPlaceholderText("e.g., 587")
        settings_form_layout.addRow("SMTP Port:", self.smtp_port_input)

        self.smtp_username_input = QLineEdit()
        self.smtp_username_input.setPlaceholderText("Your email address (e.g., your_email@example.com)")
        settings_form_layout.addRow("SMTP Username:", self.smtp_username_input)

        self.smtp_password_input = QLineEdit()
        self.smtp_password_input.setEchoMode(QLineEdit.Password) 
        self.smtp_password_input.setPlaceholderText("Your email password or app password")
        settings_form_layout.addRow("SMTP Password:", self.smtp_password_input)

        self.sender_email_input = QLineEdit()
        self.sender_email_input.setPlaceholderText("Email address to appear as sender (e.g., your_email@example.com)")
        settings_form_layout.addRow("Sender Email:", self.sender_email_input)
        
        self.settings_save_button = QPushButton("Save Email Settings")
        self.settings_save_button.clicked.connect(self.save_settings)
        settings_form_layout.addRow("", self.settings_save_button) 
        
        layout.addWidget(settings_form_group)
        layout.addStretch() 

    # --- Data and UI Management ---

    def show_notification(self, message, is_error=False):
        self.notification_label.setText(message)
        self.notification_label.setStyleSheet(f"color: {'red' if is_error else 'green'}; font-weight: bold;")
        self.notification_label.setVisible(True)
        QTimer.singleShot(5000, lambda: self.notification_label.setVisible(False))

    def load_webhooks(self):
        webhooks = self.config_manager.get_webhooks()
        self.webhook_table.setRowCount(len(webhooks))
        for row, webhook in enumerate(webhooks):
            self.webhook_table.setItem(row, 0, QTableWidgetItem(str(webhook.get('id', 'N/A'))))
            self.webhook_table.setItem(row, 1, QTableWidgetItem(webhook.get('name', 'N/A')))
            
            commands_snippet = webhook.get('commands', 'N/A').split('\n')[0] + "..." if len(webhook.get('commands', '')) > 50 else webhook.get('commands', 'N/A')
            self.webhook_table.setItem(row, 2, QTableWidgetItem(commands_snippet))

            self.webhook_table.setItem(row, 3, QTableWidgetItem(webhook.get('email_recipient', 'N/A')))

            # Trigger URL
            trigger_url_item = QTableWidgetItem(f"/webhook/trigger/{webhook.get('id', '')}")
            self.webhook_table.setItem(row, 4, trigger_url_item)

            # Status and Last Run
            status = webhook.get('last_run_status', 'N/A').upper()
            status_item = QTableWidgetItem(status)
            if status == 'SUCCESS':
                status_item.setForeground(Qt.darkGreen)
            elif status == 'FAILED' or status == 'ERROR':
                status_item.setForeground(Qt.red)
            elif status == 'RUNNING':
                status_item.setForeground(Qt.blue)
            self.webhook_table.setItem(row, 5, status_item)
            self.webhook_table.setItem(row, 6, QTableWidgetItem(webhook.get('last_run_timestamp', 'N/A')))

            # Actions column (buttons for Edit, Delete, View Logs, Copy URL)
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            action_layout.setSpacing(5)

            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda _, wid=webhook.get('id'): self.edit_webhook(wid))
            action_layout.addWidget(edit_btn)

            delete_btn = QPushButton("Delete")
            delete_btn.clicked.connect(lambda _, wid=webhook.get('id'): self.confirm_delete_webhook(wid))
            action_layout.addWidget(delete_btn)

            view_logs_btn = QPushButton("Logs")
            view_logs_btn.clicked.connect(lambda _, wid=webhook.get('id'): self.show_logs_dialog(wid))
            action_layout.addWidget(view_logs_btn)

            copy_url_btn = QPushButton("Copy URL")
            copy_url_btn.clicked.connect(lambda _, url_path=f"/webhook/trigger/{webhook.get('id', '')}": self.copy_url_to_clipboard(url_path))
            action_layout.addWidget(copy_url_btn)

            self.webhook_table.setCellWidget(row, 7, action_widget)
        self.webhook_table.resizeColumnsToContents()


    def add_update_webhook(self):
        name = self.webhook_name_input.text().strip()
        commands = self.webhook_commands_input.toPlainText().strip()
        email_recipient = self.webhook_email_input.text().strip()
        if not email_recipient: email_recipient = None 

        if not name or not commands:
            self.show_notification("Webhook Name and Commands are required.", is_error=True)
            return

        webhook_data = {
            "name": name,
            "commands": commands,
            "email_recipient": email_recipient
        }

        if self.current_webhook_id:
            success = self.config_manager.update_webhook(self.current_webhook_id, webhook_data)
            if success:
                self.show_notification(f"Webhook '{name}' updated successfully.")
            else:
                self.show_notification(f"Failed to update webhook '{name}'.", is_error=True)
        else:
            existing_webhooks = self.config_manager.get_webhooks()
            if any(w['name'] == name for w in existing_webhooks):
                self.show_notification(f"Webhook with name '{name}' already exists.", is_error=True)
                return

            new_id = self.config_manager.add_webhook(webhook_data)
            if new_id:
                self.show_notification(f"Webhook '{name}' added with ID {new_id}.")
            else:
                self.show_notification(f"Failed to add webhook '{name}'.", is_error=True)
        
        self.clear_form()
        self.load_webhooks() 

    def edit_webhook(self, webhook_id):
        webhook = self.config_manager.get_webhook_by_id(webhook_id)
        if webhook:
            self.current_webhook_id = webhook_id
            self.webhook_name_input.setText(webhook['name'])
            self.webhook_commands_input.setPlainText(webhook['commands'])
            self.webhook_email_input.setText(webhook['email_recipient'] if webhook['email_recipient'] else "")
            
            self.form_title.setText(f"Edit Webhook (ID: {webhook_id})")
            self.submit_button.setText("Update Webhook")
            self.cancel_edit_button.setVisible(True)
            self.test_script_output_label.setVisible(False)
            self.test_script_logs.setVisible(False)
            self.test_script_status_label.setVisible(False)
        else:
            self.show_notification("Webhook not found for editing.", is_error=True)

    def clear_form(self):
        self.current_webhook_id = None
        self.webhook_name_input.clear()
        self.webhook_commands_input.clear()
        self.webhook_email_input.clear()
        self.form_title.setText("Add New Webhook")
        self.submit_button.setText("Add Webhook")
        self.cancel_edit_button.setVisible(False)
        self.test_script_output_label.setVisible(False)
        self.test_script_logs.setVisible(False)
        self.test_script_status_label.setVisible(False)
        self.test_script_logs.clear()
        self.test_script_status_label.clear()
        self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #48bb78; border-radius: 5px; padding: 5px;")


    def confirm_delete_webhook(self, webhook_id):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setText(f"Are you sure you want to delete webhook ID {webhook_id}?")
        msg_box.setWindowTitle("Confirm Deletion")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        
        reply = msg_box.exec_()
        if reply == QMessageBox.Yes:
            self.delete_webhook(webhook_id)

    def delete_webhook(self, webhook_id):
        success = self.config_manager.delete_webhook(webhook_id)
        if success:
            self.show_notification(f"Webhook ID {webhook_id} deleted successfully.")
            self.load_webhooks()
            if self.current_webhook_id == webhook_id: 
                self.clear_form()
        else:
            self.show_notification(f"Failed to delete webhook ID {webhook_id}.", is_error=True)

    def update_webhook_status_in_table(self, webhook_id, status, timestamp, logs):
        for row in range(self.webhook_table.rowCount()):
            item_id = self.webhook_table.item(row, 0)
            if item_id and int(item_id.text()) == webhook_id:
                status_item = self.webhook_table.item(row, 5)
                time_item = self.webhook_table.item(row, 6)

                if status_item:
                    status_item.setText(status.upper())
                    if status == 'success':
                        status_item.setForeground(Qt.darkGreen)
                    elif status == 'failed' or status == 'error':
                        status_item.setForeground(Qt.red)
                    elif status == 'running':
                        status_item.setForeground(Qt.blue)
                
                if time_item:
                    time_item.setText(timestamp)
                
                logger.info(f"GUI updated for webhook ID {webhook_id} with status {status}.")
                break


    def show_logs_dialog(self, webhook_id):
        webhook = self.config_manager.get_webhook_by_id(webhook_id)
        if not webhook:
            self.show_notification("Logs not found for this webhook.", is_error=True)
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Logs for Webhook: {webhook.get('name', 'N/A')} (ID: {webhook_id})")
        dialog.setGeometry(200, 200, 800, 600)
        
        dialog_layout = QVBoxLayout(dialog)
        
        dialog_layout.addWidget(QLabel(f"<b>Status:</b> {webhook.get('last_run_status', 'N/A').upper()}"))
        dialog_layout.addWidget(QLabel(f"<b>Last Run:</b> {webhook.get('last_run_timestamp', 'N/A')}"))
        
        log_text_edit = QTextEdit()
        log_text_edit.setReadOnly(True)
        log_text_edit.setFont(QFont("Monospace", 9))
        
        logs_content = webhook.get('last_run_logs', 'No logs available.')
        log_text_edit.setPlainText(logs_content)

        if webhook.get('last_run_status') == 'failed' or webhook.get('last_run_status') == 'error':
            log_text_edit.setStyleSheet("background-color: #1a202c; color: #ef4444; border-radius: 5px; padding: 5px;")
        elif webhook.get('last_run_status') == 'running':
             log_text_edit.setStyleSheet("background-color: #1a202c; color: #f59e0b; border-radius: 5px; padding: 5px;")
        else:
            log_text_edit.setStyleSheet("background-color: #1a202c; color: #48bb78; border-radius: 5px; padding: 5px;")


        dialog_layout.addWidget(log_text_edit)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        dialog_layout.addWidget(close_button, alignment=Qt.AlignRight)
        
        dialog.exec_()


    def copy_url_to_clipboard(self, url_path):
        current_ip = self.local_ip_label.text().replace("Local IP: ", "").strip()
        current_port = self.server_port_label.text().replace("Port: ", "").strip()
        
        if current_ip == "N/A" or current_port == "N/A":
            self.show_notification("Server is not running or IP/Port not available.", is_error=True)
            return

        full_url = f"http://{current_ip}:{current_port}{url_path}"
        QApplication.clipboard().setText(full_url)
        self.show_notification(f"URL copied: {full_url}", is_error=False)


    # --- Server Management ---
    
    def get_local_ip(self):
        """Attempts to get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) 
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1" 

    def get_public_ip(self):
        """Attempts to get the public IP address using an external service."""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            response.raise_for_status() 
            return response.json()['ip']
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not retrieve public IP: {e}. Check internet connection or firewall.")
            return "N/A (Check Internet)"
        except Exception as e:
            logger.warning(f"An unexpected error occurred while getting public IP: {e}")
            return "N/A (Error)"

    def start_server(self):
        if self.webhook_server_thread and self.webhook_server_thread.is_alive():
            self.show_notification("Server is already running.", is_error=True)
            return

        try:
            self.server_log_output.clear()
            logger.info("Starting CI/CD Webhook Server...") 

            host = '0.0.0.0' 
            port = 8080 # Changed port from 5000 to 8080

            self.webhook_server_thread = FlaskServerThread(host, port, self.server_message_queue, self.config_manager)
            self.webhook_server_thread.daemon = True 
            self.webhook_server_thread.start()

            self.server_status_label.setText("Status: Starting...")
            self.server_status_label.setStyleSheet("font-weight: bold; color: orange;")
            self.start_server_button.setEnabled(False)
            self.stop_server_button.setEnabled(True)
            self.show_notification("Server starting...", is_error=False)

            QTimer.singleShot(1000, self._display_server_network_info)

        except Exception as e:
            self.show_notification(f"Failed to start server: {e}", is_error=True)
            logger.error(f"Error starting server: {e}") 
            self.server_status_label.setText("Status: Failed to Start")
            self.server_status_label.setStyleSheet("font-weight: bold; color: red;")
            self.start_server_button.setEnabled(True)
            self.stop_server_button.setEnabled(False)

    def _display_server_network_info(self):
        local_ip = self.get_local_ip()
        public_ip = self.get_public_ip()
        port = 8080 # Updated to 8080

        self.server_message_queue.put(('server_startup_info', local_ip, port, public_ip, f"http://{local_ip}:{port}/webhook/trigger/{{id}}"))

    def update_server_status_display(self, local_ip, port, public_ip, base_url):
        self.server_status_label.setText("Status: Running")
        self.server_status_label.setStyleSheet("font-weight: bold; color: green;")
        self.local_ip_label.setText(f"Local IP: {local_ip}")
        self.public_ip_label.setText(f"Public IP: {public_ip}")
        self.server_port_label.setText(f"Port: {port}")
        self.base_trigger_url_label.setText(f"Base Trigger URL: {base_url}")
        self.show_notification("Server is running.", is_error=False)


    def stop_server(self):
        if self.webhook_server_thread and self.webhook_server_thread.is_alive():
            self.webhook_server_thread.stop() 
            self.webhook_server_thread.join(timeout=2) 
            if self.webhook_server_thread.is_alive():
                logger.warning("Server thread did not terminate gracefully.") 
                self.show_notification("Server stopped, but thread may still be active. Restart app if issues persist.", is_error=True)
            else:
                self.show_notification("Server stopped successfully.", is_error=False)
            self.webhook_server_thread = None
        else:
            self.show_notification("Server is not running.", is_error=True)

        self.server_status_label.setText("Status: Stopped")
        self.server_status_label.setStyleSheet("font-weight: bold; color: red;")
        self.start_server_button.setEnabled(True)
        self.stop_server_button.setEnabled(False)
        self.local_ip_label.setText("Local IP: N/A")
        self.public_ip_label.setText("Public IP: N/A")
        self.server_port_label.setText("Port: N/A")
        self.base_trigger_url_label.setText("Base Trigger URL: N/A")
        logger.info("CI/CD Webhook Server stopped.") 

    def show_server_error(self, error_message):
        self.server_status_label.setText(f"Status: Error - {error_message}")
        self.server_status_label.setStyleSheet("font-weight: bold; color: red;")
        self.show_notification(f"Server Error: {error_message}", is_error=True)
        self.start_server_button.setEnabled(True)
        self.stop_server_button.setEnabled(False)
        logger.error(f"Server Error: {error_message}") 

    # --- Script Testing ---

    def test_commands(self):
        commands = self.webhook_commands_input.toPlainText().strip()
        if not commands:
            self.show_notification("No commands to test.", is_error=True)
            return

        self.test_script_output_label.setVisible(True)
        self.test_script_logs.setVisible(True)
        self.test_script_status_label.setVisible(True)
        
        self.test_script_logs.clear()
        self.test_script_logs.setText("Running test script...")
        self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #f59e0b; border-radius: 5px; padding: 5px;")
        self.test_script_status_label.setText("Status: Running...")
        self.test_script_status_label.setStyleSheet("color: blue;")

        threading.Thread(target=self._run_test_commands_in_background, args=(commands,)).start()

    def _run_test_commands_in_background(self, commands):
        try:
            process = subprocess.Popen(
                commands,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.getcwd()
            )

            output_lines = []
            for line in process.stdout:
                output_lines.append(line.strip())
                QApplication.processEvents() 

            process.wait()
            full_logs = "\n".join(output_lines)
            exit_code = process.returncode
            status = "success" if exit_code == 0 else "failed"

            QApplication.instance().postEvent(self, self.TestScriptResultEvent(status, exit_code, full_logs))

        except Exception as e:
            logger.error(f"Error during script test: {e}")
            QApplication.instance().postEvent(self, self.TestScriptResultEvent('error', -1, str(e)))

    class TestScriptResultEvent(QEvent):
        EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

        def __init__(self, status, exit_code, logs):
            super().__init__(self.EVENT_TYPE)
            self.status = status
            self.exit_code = exit_code
            self.logs = logs

    def customEvent(self, event):
        if event.type() == self.TestScriptResultEvent.EVENT_TYPE:
            self.update_test_script_ui(event.status, event.exit_code, event.logs)
        else:
            super().customEvent(event)

    def update_test_script_ui(self, status, exit_code, logs):
        self.test_script_logs.setPlainText(logs)
        if status == 'success':
            self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #48bb78; border-radius: 5px; padding: 5px;")
            self.test_script_status_label.setText(f"Status: Success (Exit Code: {exit_code})")
            self.test_script_status_label.setStyleSheet("color: green;")
        elif status == 'failed':
            self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #ef4444; border-radius: 5px; padding: 5px;")
            self.test_script_status_label.setText(f"Status: Failed (Exit Code: {exit_code})")
            self.test_script_status_label.setStyleSheet("color: red;")
        else: 
            self.test_script_logs.setStyleSheet("background-color: #1a202c; color: #ef4444; border-radius: 5px; padding: 5px;")
            self.test_script_status_label.setText(f"Status: Error - {logs}")
            self.test_script_status_label.setStyleSheet("color: red;")


    # --- Settings Management ---
    
    def load_settings(self):
        settings = self.config_manager.get_settings()
        self.smtp_server_input.setText(settings.get('smtp_server', ''))
        self.smtp_port_input.setText(str(settings.get('smtp_port', '')))
        self.smtp_username_input.setText(settings.get('smtp_username', ''))
        self.smtp_password_input.setText(settings.get('smtp_password', ''))
        self.sender_email_input.setText(settings.get('sender_email', ''))

    def save_settings(self):
        settings = {
            "smtp_server": self.smtp_server_input.text().strip(),
            "smtp_port": int(self.smtp_port_input.text().strip()) if self.smtp_port_input.text().strip().isdigit() else 587,
            "smtp_username": self.smtp_username_input.text().strip(),
            "smtp_password": self.smtp_password_input.text().strip(),
            "sender_email": self.sender_email_input.text().strip()
        }
        self.config_manager.save_settings(settings)
        self.show_notification("Email settings saved successfully.")

    # --- Application Shutdown ---
    def closeEvent(self, event):
        """Handle application close event."""
        if self.webhook_server_thread and self.webhook_server_thread.is_alive():
            reply = QMessageBox.question(self, 'Quit Application',
                                         "The webhook server is still running. Do you want to stop it and quit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.stop_server()
                QApplication.instance().processEvents() 
                if self.webhook_server_thread and self.webhook_server_thread.is_alive():
                     logger.warning("Server thread did not stop gracefully before exiting.")
                root_logger.removeHandler(self.log_handler)
                self.message_processor.stop() 
                event.accept()
            else:
                event.ignore()
        else:
            root_logger.removeHandler(self.log_handler)
            self.message_processor.stop() 
            event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    app.setStyle("Fusion") 

    main_app = CICDApp()
    main_app.show()
    sys.exit(app.exec_())
