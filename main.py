import os
import shutil
import subprocess
from datetime import datetime
from OpenSSL import crypto
import requests
import config

def dc_alert(payload:str) -> None:
    json = {}
    headers = {}

    if config.NOTIFICATION_SERVICE is not None:
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

    if config.WEBHOOK_URL is not None:
        requests.post(config.WEBHOOK_URL, json, headers, timeout=10)

def main():
    # Check if remote is ssh accessible
    try:
        subprocess.run(['ssh',"-T",f"root@{config.REMOTE_URL}", "exit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        dc_alert(f"Error while running script: {e}")
        return

    # Remove local certs
    for f in os.listdir(config.LOCAL_CERT_LOCATION):
        os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

    # Get latest cert from VPS to Docker NGINX Cert folder
    os.system(f"rsync -t root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/privkey*.pem {config.LOCAL_CERT_LOCATION}")
    os.system(f"rsync -t root@{config.REMOTE_URL}:{config.REMOTE_CERT_LOCATION}/fullchain*.pem {config.LOCAL_CERT_LOCATION}")

    # Sort by cert's numbering if there are multiple
    all_cert = os.listdir(config.LOCAL_CERT_LOCATION)

    # If have number, remove the string and sort by number, get largest int (latest cert), and combine back to string
    priv = [cert for cert in all_cert if "privkey" in cert]
    priv = "privkey" + str(sorted([int(i.replace("privkey","").replace(".pem", "")) for i in priv])[-1]) + ".pem"
    fullchain = [cert for cert in all_cert if "fullchain" in cert]
    fullchain = "fullchain" + str(sorted([int(i.replace("fullchain","").replace(".pem", "")) for i in fullchain])[-1]) + ".pem"

    # Rename the latest privkey and fullchain strip out the number
    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{priv}", f"{config.LOCAL_CERT_LOCATION}/privkey.pem")
    shutil.copy2(f"{config.LOCAL_CERT_LOCATION}/{fullchain}", f"{config.LOCAL_CERT_LOCATION}/fullchain.pem")

    # Remove everything in local except new cert
    for f in os.listdir(config.LOCAL_CERT_LOCATION):
        if f!="privkey.pem" and f!="fullchain.pem":
            os.remove(os.path.join(config.LOCAL_CERT_LOCATION, f))

    # Notify in Discord the new expiration date
    with open(f'{config.LOCAL_CERT_LOCATION}/fullchain.pem', 'rb') as fullchain_pem:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain_pem.read())
        not_after = cert.get_notAfter()
        if not_after is not None:
            not_after = not_after.decode('utf-8')
            expire_time = datetime.strptime(not_after,"%Y%m%d%H%M%SZ")
            dc_alert(f"Grabbed new Let's Encrypt certificates, expire on {expire_time}")
        else:
            dc_alert("Failed to get expiration date from the certificate.")

if __name__ == "__main__":
    main()
