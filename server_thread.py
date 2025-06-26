import os
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import socket
import requests
import time
import logging
from flask import Flask, request, jsonify, render_template_string
from queue import Queue

# Configure Flask app logger to be independent or inherit from main
# For production, consider external log management.
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
# Prevent Flask from adding its own handlers if not desired, or configure them.
# For simplicity, we'll let it use the root logger configured in main.py.


# --- Flask App (to be run in a separate thread) ---
app = Flask(__name__)

# This queue will be used to send messages/signals back to the main GUI thread
# E.g., for updating logs, status.
# The main app will pass this queue when starting the server thread.
message_queue = None
config_manager = None # Will be passed from main app

# --- Helper Functions ---

def send_email_notification(recipient, subject, body, smtp_settings):
    """Sends an email notification using provided SMTP settings."""
    smtp_server = smtp_settings.get('smtp_server')
    smtp_port = smtp_settings.get('smtp_port')
    smtp_username = smtp_settings.get('smtp_username')
    smtp_password = smtp_settings.get('smtp_password')
    sender_email = smtp_settings.get('sender_email')

    if not all([smtp_server, smtp_port, smtp_username, smtp_password, sender_email]):
        log.error("Email configuration is incomplete. Cannot send email.")
        return False

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        log.info(f"Email sent successfully to {recipient} with subject: {subject}")
        return True
    except Exception as e:
        log.error(f"Failed to send email to {recipient}: {e}")
        return False

def execute_script_and_update_gui(webhook_id, commands, email_recipient):
    """
    Executes the given commands in a subprocess, sends updates to GUI,
    and handles email notifications.
    """
    timestamp_start = time.strftime('%Y-%m-%d %H:%M:%S')
    log_message = "Script execution started..."
    
    # Send initial 'running' status to GUI
    if message_queue and config_manager:
        config_manager.update_webhook_status_and_logs(webhook_id, 'running', timestamp_start, log_message)
        message_queue.put(('update_webhook_status', webhook_id, 'running', timestamp_start, log_message))

    full_logs = ""
    status = "error"
    exit_code = -1

    try:
        log.info(f"Executing commands for webhook ID {webhook_id}...")
        
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
            log.info(f"[Webhook {webhook_id}]: {line.strip()}")
            # Optional: send incremental logs to GUI (can be noisy for fast scripts)
            # if message_queue:
            #     message_queue.put(('append_webhook_log', webhook_id, line.strip()))

        process.wait()
        full_logs = "\n".join(output_lines)
        exit_code = process.returncode
        status = "success" if exit_code == 0 else "failed"
        log_message = f"Script finished with exit code {exit_code}.\n\nLogs:\n{full_logs}"

        log.info(f"Webhook ID {webhook_id} finished with status: {status}")

    except Exception as e:
        status = "error"
        error_message = f"An error occurred during script execution for webhook ID {webhook_id}: {e}"
        log.error(error_message)
        full_logs = error_message
        log_message = error_message

    finally:
        timestamp_end = time.strftime('%Y-%m-%d %H:%M:%S')
        # Update database and send final status to GUI
        if message_queue and config_manager:
            config_manager.update_webhook_status_and_logs(webhook_id, status, timestamp_end, log_message)
            message_queue.put(('update_webhook_status', webhook_id, status, timestamp_end, log_message))

        # Send email notification
        if email_recipient and config_manager:
            smtp_settings = config_manager.get_settings()
            subject = f"[CI/CD] Deployment {status.upper()} for Webhook ID {webhook_id}"
            body = f"Deployment for webhook '{webhook_id}' {status} at {timestamp_end}.\n\n" \
                   f"Commands executed:\n{commands}\n\n" \
                   f"--- Logs ---\n{full_logs}\n\n" \
                   f"Exit Code: {exit_code}"
            send_email_notification(email_recipient, subject, body, smtp_settings)

# --- Flask Routes ---

@app.route('/webhook/trigger/<int:webhook_id>', methods=['POST'])
def trigger_webhook_by_id(webhook_id):
    """
    Endpoint for external services (like Bitbucket) to trigger a deployment.
    """
    if not config_manager:
        log.error("Config manager not initialized in server thread.")
        return jsonify({'error': 'Server not fully initialized.'}), 500

    webhook = config_manager.get_webhook_by_id(webhook_id)

    if webhook:
        commands = webhook['commands']
        email_recipient = webhook['email_recipient']
        log.info(f"Webhook ID {webhook_id} triggered. Starting script execution in background.")
        
        # Run the script in a separate thread to prevent blocking the HTTP response
        threading.Thread(target=execute_script_and_update_gui, args=(webhook_id, commands, email_recipient)).start()
        return jsonify({'message': f'Webhook ID {webhook_id} received and script execution initiated.'}), 200
    else:
        return jsonify({'error': 'Webhook not found.'}), 404

@app.route('/webhook/test_script', methods=['POST'])
def test_script_endpoint():
    """Endpoint to test a script directly from the UI (simulated call)."""
    data = request.json
    commands = data.get('commands')

    if not commands:
        return jsonify({'error': 'Commands are required for testing.'}), 400

    try:
        log.info("Testing script...")
        process = subprocess.Popen(
            commands,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=os.getcwd()
        )

        output = []
        for line in process.stdout:
            output.append(line.strip())
            time.sleep(0.01) # Simulate some work

        process.wait()
        full_logs = "\n".join(output)
        exit_code = process.returncode
        status = "success" if exit_code == 0 else "failed"

        log.info(f"Script test finished with status: {status}")
        return jsonify({'status': status, 'exit_code': exit_code, 'logs': full_logs})

    except Exception as e:
        log.error(f"Error during script test: {e}")
        return jsonify({'status': 'error', 'logs': str(e)}), 500


class FlaskServerThread(threading.Thread):
    """
    Thread to run the Flask web server.
    """
    def __init__(self, host, port, queue, cm_instance):
        super().__init__()
        self.host = host
        self.port = port
        self.queue = queue
        global message_queue
        message_queue = queue # Make queue available to Flask routes
        global config_manager
        config_manager = cm_instance # Make config manager available

        # This will store the werkzeug.serving.run_simple server instance
        self.server = None
        self.running = threading.Event() # Event to signal server to stop

    def run(self):
        log.info(f"Flask server thread started on http://{self.host}:{self.port}")
        self.running.set() # Set the flag to indicate server is running

        try:
            # Use werkzeug's run_simple for controlled shutdown
            from werkzeug.serving import run_simple
            self.server = run_simple(self.host, self.port, app, threaded=True, use_reloader=False, use_debugger=False)
        except Exception as e:
            log.error(f"Flask server failed to start: {e}")
            if self.queue:
                self.queue.put(('server_error', str(e)))
        finally:
            log.info("Flask server thread stopped.")
            self.running.clear() # Clear the flag when server stops

    def stop(self):
        """Stops the Flask server."""
        if self.server:
            # This is a bit tricky with run_simple; typically you'd need
            # to send a request to a shutdown endpoint, or use a context manager.
            # For simplicity, we'll rely on the thread ending naturally or
            # the parent process terminating.
            # A more robust shutdown for run_simple would involve:
            # from werkzeug.serving import make_server
            # self.server = make_server(self.host, self.port, app)
            # self.server.serve_forever()
            # then in stop: self.server.shutdown()
            # For this simple example, we'll let it terminate with the app or on its own.
            log.info("Attempting to stop Flask server thread (graceful shutdown might not be immediate).")
            # In a real app, you'd send a request to a shutdown endpoint or use a more advanced server
            # like Gunicorn/Waitress which can be stopped via signals.
            # For now, rely on main process exit or a clean stop by stopping the event loop in `run_simple`
            # This simple example relies on run_simple eventually detecting the thread exit.
            pass
        self.running.clear()
