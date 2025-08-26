import os
import logging
import shutil
import subprocess
from datetime import datetime
from OpenSSL import crypto
import requests
import config

logger = logging.getLogger(__name__)

def setup_logging():
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if config.VERBOSE:
        if config.VERBOSE.lower() == "debug":
            logging.basicConfig(level=logging.DEBUG, format=format_str)
        elif config.VERBOSE.lower() == "info":
            logging.basicConfig(level=logging.INFO, format=format_str)
        else:
            # This is for "Error" value or anything else
            logging.basicConfig(level=logging.ERROR, format=format_str)
    else:
        logging.basicConfig(level=logging.ERROR, format=format_str)

def dc_alert(payload:str) -> None:
    json = {}
    headers = {}

    if config.NOTIFICATION_SERVICE and config.WEBHOOK_URL:
        logger.debug("Notification service: %s and webhook url: %s", config.NOTIFICATION_SERVICE, config.WEBHOOK_URL)
        if config.NOTIFICATION_SERVICE.lower() == "apprise":
            json = {
                "body": payload,
                "tags": config.APPRISE_TAG if config.APPRISE_TAG else "all"
            }
        elif config.NOTIFICATION_SERVICE.lower() == "discord":
            json = {
                "content": payload
            }
            headers = {
                "Content-Type": "application/json"
            }

        try:
            response = requests.post(config.WEBHOOK_URL, json=json, headers=headers, timeout=10)
            response.raise_for_status()
            logger.info("Notification sent successfully")
        except requests.RequestException as e:
            logger.error("Failed to send notification: %s", e)
    else:
        logger.info("Skip Discord notification!")

def get_remote_cert():
    # Check if remote is ssh accessible
    try:
        cmd = ['ssh',"-T",f"root@{config.REMOTE_URL}", "exit"]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        # In case this message does not get rendered, f-string will still cause a render anyway, while %s rendering will be determine by logger class
        logger.error("Error while running script: %s", e)
        dc_alert(f"Error while running script: {e}")
        exit(1)

    # Check remote have cert at all
    cmd = ["ssh", f"root@{config.REMOTE_URL}", f"cd {config.REMOTE_CERT_LOCATION} && ls"]
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    logger.debug("Got %s certificates from remote", int(len(process.stdout.strip().split("\n"))/2)) # Fullchain and PrivKey is a pair
    if (len(process.stdout.strip().split("\n")) == 0):
        logger.error("Cert location does not have any certificate, exiting")
        dc_alert("Cert location does not have any certificate, exiting")
        exit(0)

    # Remove local certs
    local_cert_dir = os.listdir(config.LOCAL_CERT_LOCATION)
    logger.info("Removing %s files", config.LOCAL_CERT_LOCATION)
    logger.debug("Removing %s", local_cert_dir)
    for f in local_cert_dir:
        os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

    # Rsync certs to local
    logger.info("Rsync certificates from %s", config.REMOTE_CERT_LOCATION)
    try:
        cmd = ["rsync", "--archive", f"root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/privkey*.pem", config.LOCAL_CERT_LOCATION]
        subprocess.run(cmd, check=True)

        cmd = ["rsync", "--archive", f"root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/fullchain*.pem", config.LOCAL_CERT_LOCATION ]
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        # In case this message does not get rendered, f-string will still cause a render anyway, while %s rendering will be determine by logger class
        logger.error("Error while running rsync: %s", e)
        dc_alert(f"Error while running rsync: {e}")
        exit(1)

def update_to_latest_cert():
    logger.info("Sorting by latest certificate and replace existing cert at %s", config.LOCAL_CERT_LOCATION)
    # Sort by cert's numbering if there are multiple
    all_cert = os.listdir(config.LOCAL_CERT_LOCATION)

    # If have number, remove the string and sort by number, get largest int (latest cert), and combine back to string
    priv = [cert for cert in all_cert if "privkey" in cert]
    priv = "privkey" + str(sorted([int(i.replace("privkey","").replace(".pem", "")) for i in priv])[-1]) + ".pem"
    logger.debug("Found latest privkey: %s", priv)

    fullchain = [cert for cert in all_cert if "fullchain" in cert]
    fullchain = "fullchain" + str(sorted([int(i.replace("fullchain","").replace(".pem", "")) for i in fullchain])[-1]) + ".pem"
    logger.debug("Found latest fullchain: %s", fullchain)

    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{priv}", f"{config.LOCAL_CERT_LOCATION}/privkey.pem")
    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{fullchain}", f"{config.LOCAL_CERT_LOCATION}/fullchain.pem")

    # Remove everything in local except new cert
    local_cert_dir = [cert for cert in os.listdir(config.LOCAL_CERT_LOCATION) if cert != "privkey.pem" and cert != "fullchain.pem"]
    logger.info("Remove everything but latest privkey and fullchain")
    logger.debug("Removing %s", local_cert_dir)
    for f in local_cert_dir:
        os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

def main():
    logger.info("Starting certificate synchronization from %s to %s", config.REMOTE_CERT_LOCATION, config.LOCAL_CERT_LOCATION)
    get_remote_cert()
    update_to_latest_cert()

    try:
        # Notify in Discord the new expiration date
        with open(f'{config.LOCAL_CERT_LOCATION}/fullchain.pem', 'rb') as fullchain_pem:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain_pem.read())
            not_after = cert.get_notAfter()
            if not_after:
                not_after = not_after.decode('utf-8')
                expire_time = datetime.strptime(not_after,"%Y%m%d%H%M%SZ")
                logger.info("Certificate %s will expire on: %s", config.LOCAL_CERT_LOCATION+"/fullchain.pem", expire_time)
                dc_alert(f"Grabbed new Let's Encrypt certificates, expire on {expire_time}")
            else:
                logger.error("Failed to get expiration date from the certificate %s.", config.LOCAL_CERT_LOCATION+"/fullchain.pem")
                dc_alert("Failed to get expiration date from the certificate.")
    except (FileNotFoundError, IOError) as e:
        logger.error("Certificate failed parsing with exception %s", e)
        dc_alert(f"Certificate failed parsing with exception {e}")
        exit(1)

if __name__ == "__main__":
    setup_logging()
    main()
