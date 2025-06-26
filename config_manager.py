import json
import os
import logging
import platform # Added for cross-platform path handling

# Set up basic logging for this module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigManager:
    """
    Handles loading and saving application configuration and webhook data
    to a JSON file, located in a persistent user-specific application data directory.
    """
    def __init__(self, app_name='CICDTool', filename='cicd_data.json'):
        self.app_name = app_name
        self.filename = filename
        self.app_data_dir = self._get_app_data_directory()
        self.full_filepath = os.path.join(self.app_data_dir, self.filename)
        
        # Ensure the directory exists
        os.makedirs(self.app_data_dir, exist_ok=True)
        logging.info(f"Application data directory: {self.app_data_dir}")

        self.data = self._load_data()

    def _get_app_data_directory(self):
        """
        Determines the appropriate user-specific application data directory
        based on the operating system.
        """
        system = platform.system()
        if system == "Windows":
            # On Windows, use %APPDATA% or %LOCALAPPDATA%
            # LOCALAPPDATA is usually preferred for non-roaming app data
            return os.path.join(os.getenv('LOCALAPPDATA') or os.getenv('APPDATA'), self.app_name)
        elif system == "Darwin": # macOS
            return os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', self.app_name)
        else: # Linux and other Unix-like systems
            # Follow XDG Base Directory Specification, or fallback to ~/.config
            xdg_config_home = os.getenv('XDG_CONFIG_HOME')
            if xdg_config_home:
                return os.path.join(xdg_config_home, self.app_name)
            return os.path.join(os.path.expanduser('~'), '.config', self.app_name)


    def _load_data(self):
        """Loads data from the JSON file. Initializes with defaults if file doesn't exist."""
        if not os.path.exists(self.full_filepath):
            logging.info(f"Config file '{self.full_filepath}' not found. Creating with default structure.")
            # Default structure for initial data
            default_data = {
                "webhooks": [],
                "settings": {
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "smtp_username": "",
                    "smtp_password": "",
                    "sender_email": ""
                }
            }
            self._save_data(default_data) # Save default data
            return default_data
        
        try:
            with open(self.full_filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Ensure structure for existing files in case of previous versions
                if "webhooks" not in data:
                    data["webhooks"] = []
                if "settings" not in data:
                    data["settings"] = {
                        "smtp_server": "smtp.gmail.com",
                        "smtp_port": 587,
                        "smtp_username": "",
                        "smtp_password": "",
                        "sender_email": ""
                    }
                logging.info(f"Data loaded from '{self.full_filepath}'.")
                return data
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from '{self.full_filepath}': {e}. Re-initializing file.")
            # If JSON is corrupted, create a fresh file
            return self._load_data() # Recursive call to create default data
        except Exception as e:
            logging.error(f"Unexpected error loading config from '{self.full_filepath}': {e}. Re-initializing file.")
            return self._load_data()

    def _save_data(self, data):
        """Saves data to the JSON file."""
        try:
            with open(self.full_filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            logging.info(f"Data saved to '{self.full_filepath}'.")
        except Exception as e:
            logging.error(f"Error saving data to '{self.full_filepath}': {e}")

    def get_webhooks(self):
        """Returns the list of webhooks."""
        # Reload data to ensure we have the latest from disk
        self.data = self._load_data() 
        return self.data.get("webhooks", [])

    def add_webhook(self, webhook):
        """Adds a new webhook. Assigns a unique ID."""
        self.data = self._load_data() # Ensure latest data before modifying
        webhooks = self.data.get("webhooks", [])
        # Assign a new ID (simple increment, consider UUIDs for more robustness)
        webhook_id = max([w['id'] for w in webhooks] + [0]) + 1
        webhook['id'] = webhook_id
        # Initialize status fields
        webhook['last_run_status'] = 'N/A'
        webhook['last_run_timestamp'] = 'N/A'
        webhook['last_run_logs'] = 'No logs available.'
        webhooks.append(webhook)
        self.data["webhooks"] = webhooks
        self._save_data(self.data)
        logging.info(f"Webhook '{webhook.get('name')}' added with ID {webhook_id}.")
        return webhook_id

    def update_webhook(self, webhook_id, updated_data):
        """Updates an existing webhook."""
        self.data = self._load_data() # Ensure latest data before modifying
        webhooks = self.data.get("webhooks", [])
        found = False
        for i, webhook in enumerate(webhooks):
            if webhook['id'] == webhook_id:
                # Preserve existing last_run_status, timestamp, logs unless explicitly updated
                updated_data['last_run_status'] = updated_data.get('last_run_status', webhook.get('last_run_status', 'N/A'))
                updated_data['last_run_timestamp'] = updated_data.get('last_run_timestamp', webhook.get('last_run_timestamp', 'N/A'))
                updated_data['last_run_logs'] = updated_data.get('last_run_logs', webhook.get('last_run_logs', 'No logs available.'))
                
                webhooks[i] = {**webhook, **updated_data} # Merge existing with updated
                found = True
                break
        if found:
            self.data["webhooks"] = webhooks
            self._save_data(self.data)
            logging.info(f"Webhook ID {webhook_id} updated.")
        return found

    def delete_webhook(self, webhook_id):
        """Deletes a webhook by ID."""
        self.data = self._load_data() # Ensure latest data before modifying
        initial_count = len(self.data.get("webhooks", []))
        self.data["webhooks"] = [w for w in self.data.get("webhooks", []) if w['id'] != webhook_id]
        if len(self.data["webhooks"]) < initial_count:
            self._save_data(self.data)
            logging.info(f"Webhook ID {webhook_id} deleted.")
            return True
        return False

    def get_webhook_by_id(self, webhook_id):
        """Retrieves a single webhook by ID."""
        self.data = self._load_data() # Ensure latest data before retrieving
        for webhook in self.data.get("webhooks", []):
            if webhook['id'] == webhook_id:
                return webhook
        return None

    def get_settings(self):
        """Returns the application settings."""
        self.data = self._load_data() # Ensure latest data before retrieving
        return self.data.get("settings", {})

    def save_settings(self, settings):
        """Saves the application settings."""
        self.data = self._load_data() # Ensure latest data before modifying
        self.data["settings"] = settings
        self._save_data(self.data)
        logging.info("Application settings saved.")

    def update_webhook_status_and_logs(self, webhook_id, status, timestamp, logs):
        """Updates the status and logs of a specific webhook."""
        self.data = self._load_data() # Ensure latest data before modifying
        webhooks = self.data.get("webhooks", [])
        found = False
        for i, webhook in enumerate(webhooks):
            if webhook['id'] == webhook_id:
                webhook['last_run_status'] = status
                webhook['last_run_timestamp'] = timestamp
                webhook['last_run_logs'] = logs
                found = True
                break
        if found:
            self.data["webhooks"] = webhooks
            self._save_data(self.data)
            logging.info(f"Webhook ID {webhook_id} status updated to '{status}'.")
        return found
