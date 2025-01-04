#!/usr/bin/env python3

import logging
import subprocess
import sys
import yaml
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
from telegram.ext import Application, MessageHandler, filters, CallbackQueryHandler
from logging.handlers import RotatingFileHandler

# Set up logging to /var/log/unbanit/unbanit.log
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = '/var/log/unbanit/unbanit.log'
log_rotate = 10  # Default log rotation (changeable via config)
log_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=log_rotate)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Read the config file (config.yml)
def read_config():
    try:
        with open("/etc/unbanit/config.yml", "r") as file:
            config = yaml.safe_load(file)
        return config
    except Exception as e:
        logger.error(f"Failed to read config file: {e}")
        sys.exit(1)

# Read configuration
config = read_config()

# Ensure jail_name is present in config
jail_name = config.get('jail_name', None)
if not jail_name:
    logger.error("Error: 'jail_name' is missing in the config.yml file.")
    sys.exit("Error: 'jail_name' is missing in the config.yml file. Please check the config.")

# Telegram token (from config)
tele_token = config.get('tele_token', None)
if not tele_token:
    logger.error("Error: 'tele_token' is missing in the config.yml file.")
    sys.exit("Error: 'tele_token' is missing in the config.yml file. Please check the config.")

# Read allowed_id from the config and handle cases where it's a list or a comma-separated string
allowed_ids = set()

if 'allowed_id' in config:
    # Check if it's a comma-separated string
    if isinstance(config['allowed_id'], str):
        allowed_ids = set(map(int, config['allowed_id'].split(',')))
    # If it's already a list, just convert it to a set of integers
    elif isinstance(config['allowed_id'], list):
        allowed_ids = set(config['allowed_id'])
    else:
        logger.error("Error: 'allowed_id' in config must be a comma-separated string or a list of integers.")
        sys.exit("Error: 'allowed_id' in config must be a comma-separated string or a list of integers.")

# Function to check if user is authorized
def is_user_authorized(user_id):
    if user_id in allowed_ids:
        return True
    # Otherwise check instances in config.yml for authorized users
    for instance in config.get('instances', []):
        for user_key, user_data in instance.items():
            if user_data.get('t_id') == user_id and user_data.get('stat') == 'active':
                return True
    return False

# Function to check if an IP address is banned in the specified Fail2Ban jail
def check_if_banned(ip_address: str, jail_name: str) -> bool:
    try:
        # Run the fail2ban-client status command to get the list of banned IPs for the jail
        result = subprocess.run(
            ['fail2ban-client', 'status', jail_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            # Look for banned IP addresses in the output
            banned_ips_output = result.stdout
            if ip_address in banned_ips_output:
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking if IP is banned: {e}")
        return False

# Function to unban the IP address if it is banned
def unban_ip_address(ip_address: str, jail_name: str) -> bool:
    try:
        # Run the fail2ban-client unban command for the specific IP
        result = subprocess.run(
            ['fail2ban-client', 'set', jail_name, 'unbanip', ip_address],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            return True
        else:
            logger.error(f"Failed to unban IP {ip_address}: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error unbanning IP {ip_address}: {e}")
        return False

# Command handler for /start
async def start(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_user_authorized(user_id):
        await update.message.reply_text("You are not authorized to use this bot.")
        return
    await update.message.reply_text("Welcome to UnbanIt Bot! You can use /check <IP> and /unban <IP> to manage IP unban.")

# Command handler for /check
async def check_ip(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_user_authorized(user_id):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    ip_address = context.args[0] if context.args else None
    if ip_address:
        # Check if the IP is banned
        is_banned = check_if_banned(ip_address, jail_name)
        if is_banned:
            await update.message.reply_text(f"IP address {ip_address} is currently banned.")
        else:
            await update.message.reply_text(f"IP address {ip_address} is not banned.")
    else:
        await update.message.reply_text("Please provide an IP address to check.")

# Command handler for /unban
async def unban_ip(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if not is_user_authorized(user_id):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    ip_address = context.args[0] if context.args else None
    if ip_address:
        # Check if the IP is banned
        is_banned = check_if_banned(ip_address, jail_name)

        if is_banned:
            # Unban the IP if it is banned
            unban_result = unban_ip_address(ip_address, jail_name)
            if unban_result:
                await update.message.reply_text(f"Successfully unbanned IP address: {ip_address}")
                logger.info(f"Successfully unbanned IP address: {ip_address} (User: {update.message.from_user.id})")
            else:
                await update.message.reply_text(f"Failed to unban IP address: {ip_address}")
                logger.error(f"Failed to unban IP address: {ip_address} (User: {update.message.from_user.id})")
        else:
            await update.message.reply_text(f"IP address {ip_address} is not banned.")
            logger.info(f"Attempted to unban IP address: {ip_address}, but it is not banned. (User: {update.message.from_user.id})")
    else:
        await update.message.reply_text("Please provide an IP address to unban.")

# Error handler for invalid commands
async def unknown(update: Update, context: CallbackContext):
    await update.message.reply_text(
        "Sorry, I didn't understand that command.\nThe following commands are available:\n/start - Start the bot.\n/check <IP> - Check if an IP is banned.\n/unban <IP> - Unban an IP."
    )

def main():
    try:
        # Set up the Application with the bot token
        application = Application.builder().token(tele_token).build()

        # Command handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("check", check_ip))
        application.add_handler(CommandHandler("unban", unban_ip))

        # Handler for unknown commands
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, unknown))

        # Run the bot
        application.run_polling()

    except Exception as e:
        logger.error(f"An error occurred while running the bot: {e}")
        sys.exit("Bot initialization failed. Please check the logs.")

if __name__ == "__main__":
    main()
