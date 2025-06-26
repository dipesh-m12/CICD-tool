import argparse
import sys
import os
import json
import logging
from pprint import pprint

# Add the parent directory to sys.path to allow importing config_manager
# This is crucial when running cli_tool.py directly or after PyInstaller bundles it
# The config_manager.py needs to be found.
# In a PyInstaller bundle, this would typically be handled by --add-data
# But for direct script execution, this helps.
script_dir = os.path.dirname(os.path.abspath(__file__))
# sys.path.append(script_dir) # Not strictly necessary if config_manager is in same dir
from config_manager import ConfigManager

# Configure a simple logger for the CLI tool
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool to manage CI/CD Webhook Desktop Server configurations.",
        formatter_class=argparse.RawTextHelpFormatter # Preserve newlines in help
    )

    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- List Webhooks Command ---
    list_parser = subparsers.add_parser("list", help="List all configured webhooks.")

    # --- Add Webhook Command ---
    add_parser = subparsers.add_parser("add", help="Add a new webhook.")
    add_parser.add_argument("--name", required=True, help="Unique name for the webhook (e.g., prod-deploy).")
    add_parser.add_argument("--commands", required=True, 
                            help="Deployment commands (shell script). Enclose in quotes if it contains spaces.\n"
                                 "Example: 'cd /app && git pull && npm install'")
    add_parser.add_argument("--email", help="Email address for notifications (optional).")

    # --- Update Webhook Command ---
    update_parser = subparsers.add_parser("update", help="Update an existing webhook by ID.")
    update_parser.add_argument("--id", type=int, required=True, help="ID of the webhook to update.")
    update_parser.add_argument("--name", help="New name for the webhook.")
    update_parser.add_argument("--commands", 
                                help="New deployment commands (shell script).\n"
                                     "Example: 'cd /app && git pull && npm install'")
    update_parser.add_argument("--email", help="New email address for notifications. Use 'None' to remove.")

    # --- Delete Webhook Command ---
    delete_parser = subparsers.add_parser("delete", help="Delete a webhook by ID.")
    delete_parser.add_argument("--id", type=int, required=True, help="ID of the webhook to delete.")

    # --- Show Settings Command ---
    show_settings_parser = subparsers.add_parser("show-settings", help="Show current email SMTP settings.")

    # --- Set Settings Command ---
    set_settings_parser = subparsers.add_parser("set-settings", help="Set email SMTP settings.")
    set_settings_parser.add_argument("--smtp-server", help="SMTP server address (e.g., smtp.gmail.com).")
    set_settings_parser.add_argument("--smtp-port", type=int, help="SMTP port (e.g., 587).")
    set_settings_parser.add_argument("--smtp-username", help="SMTP username (your email address).")
    set_settings_parser.add_argument("--smtp-password", help="SMTP password (or app password).")
    set_settings_parser.add_argument("--sender-email", help="Email address to appear as sender.")

    # --- Get Webhook URL Command ---
    get_url_parser = subparsers.add_parser("get-url", help="Get the full trigger URL for a webhook.")
    get_url_parser.add_argument("--id", type=int, required=True, help="ID of the webhook.")
    get_url_parser.add_argument("--server-ip", required=True, help="Public or local IP address where the CI/CD app server is running.")
    get_url_parser.add_argument("--server-port", type=int, default=8080, help="Port the CI/CD app server is listening on (default: 8080).")


    args = parser.parse_args()

    # Initialize ConfigManager
    cm = ConfigManager()

    if args.command == "list":
        webhooks = cm.get_webhooks()
        if not webhooks:
            logger.info("No webhooks configured yet.")
        else:
            logger.info(f"Configured Webhooks ({cm.full_filepath}):")
            for webhook in webhooks:
                print(f"  ID: {webhook.get('id')}")
                print(f"  Name: {webhook.get('name')}")
                print(f"  Commands: \n{webhook.get('commands')}")
                print(f"  Email Recipient: {webhook.get('email_recipient', 'N/A')}")
                print(f"  Last Run Status: {webhook.get('last_run_status', 'N/A')}")
                print(f"  Last Run Time: {webhook.get('last_run_timestamp', 'N/A')}")
                print(f"  Trigger Path: /webhook/trigger/{webhook.get('id')}")
                print("-" * 30)

    elif args.command == "add":
        webhook_data = {
            "name": args.name,
            "commands": args.commands,
            "email_recipient": args.email if args.email != 'None' else None
        }
        # Check if name already exists
        if any(w['name'] == args.name for w in cm.get_webhooks()):
            logger.error(f"Error: Webhook with name '{args.name}' already exists.")
            sys.exit(1)
        
        new_id = cm.add_webhook(webhook_data)
        if new_id:
            logger.info(f"Webhook '{args.name}' added successfully with ID: {new_id}")
        else:
            logger.error(f"Failed to add webhook '{args.name}'.")
            sys.exit(1)

    elif args.command == "update":
        webhook_id = args.id
        webhook = cm.get_webhook_by_id(webhook_id)
        if not webhook:
            logger.error(f"Error: Webhook with ID {webhook_id} not found.")
            sys.exit(1)

        update_data = {}
        if args.name is not None:
            # Check for name conflict if changing name
            if args.name != webhook['name'] and any(w['name'] == args.name for w in cm.get_webhooks() if w['id'] != webhook_id):
                logger.error(f"Error: Webhook with name '{args.name}' already exists for another webhook.")
                sys.exit(1)
            update_data['name'] = args.name
        if args.commands is not None:
            update_data['commands'] = args.commands
        if args.email is not None:
            update_data['email_recipient'] = args.email if args.email != 'None' else None

        if update_data:
            success = cm.update_webhook(webhook_id, update_data)
            if success:
                logger.info(f"Webhook ID {webhook_id} updated successfully.")
            else:
                logger.error(f"Failed to update webhook ID {webhook_id}.")
                sys.exit(1)
        else:
            logger.warning("No update arguments provided. Nothing changed.")

    elif args.command == "delete":
        confirm = input(f"Are you sure you want to delete webhook ID {args.id}? (yes/no): ").lower()
        if confirm == 'yes':
            success = cm.delete_webhook(args.id)
            if success:
                logger.info(f"Webhook ID {args.id} deleted successfully.")
            else:
                logger.error(f"Failed to delete webhook ID {args.id}. It might not exist.")
                sys.exit(1)
        else:
            logger.info("Deletion cancelled.")

    elif args.command == "show-settings":
        settings = cm.get_settings()
        if not settings:
            logger.info("No settings configured yet.")
        else:
            logger.info(f"Current Settings ({cm.full_filepath}):")
            pprint(settings) # Use pprint for nicely formatted dict output

    elif args.command == "set-settings":
        current_settings = cm.get_settings()
        update_settings = {}
        if args.smtp_server is not None:
            update_settings['smtp_server'] = args.smtp_server
        if args.smtp_port is not None:
            update_settings['smtp_port'] = args.smtp_port
        if args.smtp_username is not None:
            update_settings['smtp_username'] = args.smtp_username
        if args.smtp_password is not None:
            update_settings['smtp_password'] = args.smtp_password
        if args.sender_email is not None:
            update_settings['sender_email'] = args.sender_email

        if update_settings:
            # Merge with current settings to only update specified fields
            new_settings = {**current_settings, **update_settings}
            cm.save_settings(new_settings)
            logger.info("Email settings updated successfully.")
        else:
            logger.warning("No settings arguments provided. Nothing changed.")

    elif args.command == "get-url":
        webhook = cm.get_webhook_by_id(args.id)
        if not webhook:
            logger.error(f"Error: Webhook with ID {args.id} not found.")
            sys.exit(1)
        
        full_url = f"http://{args.server_ip}:{args.server_port}/webhook/trigger/{webhook.get('id')}"
        logger.info(f"Full Trigger URL for Webhook ID {args.id}:")
        print(full_url)
        logger.info("Remember to open port 8080 (or your configured port) in your EC2 security group.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
