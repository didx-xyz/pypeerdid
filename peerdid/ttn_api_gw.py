import time
import ttn
import os
from dotenv import load_dotenv, find_dotenv

# automatically find and load the .env file
load_dotenv(find_dotenv())

# Load sensitive info from environment variables
bot_token = os.environ.get("BOT_TOKEN")
bot_chatID = os.environ.get("BOT_CHATID")
gateway_ID_LS1 = os.environ.get("GATEWAY_ID_LS1")
USERNAME = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
HOSTNAME = os.environ.get("HOSTNAME")
PORT = os.environ.get("PORT")
app_id = os.environ.get("APP_ID")
access_key = os.environ.get("ACCESS_KEY")


def uplink_callback(msg, client):
    print("Received uplink from ", msg.dev_id)
    print(msg)


handler = ttn.HandlerClient(app_id, access_key)

# using mqtt client
# mqtt_client = handler.data()
# mqtt_client.set_uplink_callback(uplink_callback)
# mqtt_client.connect()
# time.sleep(60)
# mqtt_client.close()

# using application manager client
app_client = handler.application()
my_app = app_client.get()
print(my_app)
my_devices = app_client.devices()
print(my_devices)
