import os
import shutil
import subprocess
from datetime import datetime
from OpenSSL import crypto
import requests
import config
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO if config.VERBOSE else logging.ERROR)

def dc_alert(payload:str) -> None:
    json = {}
    headers = {}

    if config.NOTIFICATION_SERVICE and config.WEBHOOK_URL:
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

        logger.info("Discord message sent!")
        requests.post(config.WEBHOOK_URL, json, headers, timeout=10)

def main():
    # Check if remote is ssh accessible
    try:
        subprocess.run(['ssh',"-T",f"root@{config.REMOTE_URL}", "exit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        # In case this message does not get rendered, f-string will still cause a render anyway, while %s rendering will be determine by logger class
        logger.error("Error while running script: %s", e)
        dc_alert(f"Error while running script: {e}")
        exit(1)

    # Get latest cert from VPS to Docker NGINX Cert folder
    process = subprocess.run(["ssh", f"root@{config.REMOTE_URL}", f"cd {config.REMOTE_CERT_LOCATION} && ls"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    if (len(process.stdout.strip().split("\n")) == 0):
        logger.error("Cert location does not have any file, exiting")
        dc_alert("Cert location does not have any file, exiting")
        exit(0)

    logger.info("Removing %s files", config.LOCAL_CERT_LOCATION)

    # Remove local certs
    for f in os.listdir(config.LOCAL_CERT_LOCATION):
        os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

    logger.info("Rsync certbot certificates from %s", config.REMOTE_CERT_LOCATION)
    try:
        subprocess.run(["rsync", "--archive", f"root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/privkey*.pem", config.LOCAL_CERT_LOCATION ], check=True)
        subprocess.run(["rsync", "--archive", f"root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/fullchain*.pem", config.LOCAL_CERT_LOCATION ], check=True)
    except subprocess.CalledProcessError as e:
        dc_alert(f"Error while running rsync: {e}")
        # In case this message does not get rendered, f-string will still cause a render anyway, while %s rendering will be determine by logger class
        logger.error("Error while running rsync: %s", e)
        exit(1)

    # Sort by cert's numbering if there are multiple
    logger.info("Sorting latest certbot certificates if multiple presents")
    all_cert = os.listdir(config.LOCAL_CERT_LOCATION)

    # If have number, remove the string and sort by number, get largest int (latest cert), and combine back to string
    priv = [cert for cert in all_cert if "privkey" in cert]
    priv = "privkey" + str(sorted([int(i.replace("privkey","").replace(".pem", "")) for i in priv])[-1]) + ".pem"
    fullchain = [cert for cert in all_cert if "fullchain" in cert]
    fullchain = "fullchain" + str(sorted([int(i.replace("fullchain","").replace(".pem", "")) for i in fullchain])[-1]) + ".pem"

    # Rename the latest privkey and fullchain strip out the number
    logger.info("Renaming latest privkey and fullchain")
    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{priv}", f"{config.LOCAL_CERT_LOCATION}/privkey.pem")
    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{fullchain}", f"{config.LOCAL_CERT_LOCATION}/fullchain.pem")

    # Remove everything in local except new cert
    logger.info("Remove everything but latest privkey and fullchain")
    for f in os.listdir(config.LOCAL_CERT_LOCATION):
        if f!="privkey.pem" and f!="fullchain.pem":
            os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

    # Notify in Discord the new expiration date
    with open(f'{config.LOCAL_CERT_LOCATION}/fullchain.pem', 'rb') as fullchain_pem:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain_pem.read())
        not_after = cert.get_notAfter()
        if not_after:
            not_after = not_after.decode('utf-8')
            expire_time = datetime.strptime(not_after,"%Y%m%d%H%M%SZ")
            logger.info("Certificate will expire on: %s", expire_time)
            dc_alert(f"Grabbed new Let's Encrypt certificates, expire on {expire_time}")
        else:
            logger.error("Failed to get expiration date from the certificate.")
            dc_alert("Failed to get expiration date from the certificate.")

if __name__ == "__main__":
    main()
