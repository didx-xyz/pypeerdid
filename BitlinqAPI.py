import requests
import paho.mqtt.client as mqtt
import time
import datetime
import os
import sys
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

# Set other variables
timestep = 30  # seconds
limit_sentmessages = 8
version = 1.054
messages = []

gateway_ID = []
test = 0  # 1:testing option on, 0:operational mode on
mode = ["Operational", "Testing (no LN payments executed)"]
timeformat = 1  # 1:timeformat part of message, 0: timeformat is not part of message

CONNECT_RESULTS = {

    0: "Connection successful",

    1: "Connection refused - incorrect protocol version",

    2: "Connection refused - invalid client identifier",

    3: "Connection refused - server unavailable",

    4: "Connection refused - bad username or password",

    5: "Connection refused - not authorised"

}


# reports connection status

def on_connect(mqttc, mosq, obj, rc):
    print(str(datetime.datetime.now()) + ": TTN - Connected with result code " + str(rc) + " : " + CONNECT_RESULTS[rc])

    # subscribe for all devices of user

    mqttc.subscribe('#')


# reports message from device

def on_message(mqttc, obj, msg):
    # print topic i.e. ttn path with the device ID at the penultimate level and 'up'

    #    print(msg.topic)

    # print the payload using any decoder specified in ttn application
    print(msg.payload)
    #    data=msg.payload.decode('ASCII')
    data = str(msg.payload)
    start = data.find('{"text":"') + 9
    stop = data.find(',"metadata":{') - 2
    messages.append(data[start:stop])
    print(data[start:stop])
    start = data.find('{"gtw_id":"') + 11
    stop = data.find(',"timestamp":') - 1
    gateway_ID.append(data[start:stop])
    print(gateway_ID[0])


def on_publish(mosq, obj, mid):
    print(str(datetime.datetime.now()) + ": TTN - mid: " + str(mid))


def on_subscribe(mosq, obj, mid, granted_qos):
    print(str(datetime.datetime.now()) + ": TTN - Subscribed: " + str(mid) + " " + str(granted_qos))


def on_log(mqttc, obj, level, buf):
    print(str(datetime.datetime.now()) + ": TTN - message:" + str(buf))

    print(str(datetime.datetime.now()) + ": TTN - userdata:" + str(obj))


# ---------------------------------------------------
def system_checks():
    print(str(datetime.datetime.now()) + ": Check Bitcoin Node (bitcoind)")
    print(str(datetime.datetime.now()) + ": Check Lightning Network (LN) node (c-lightning)")
    print(str(datetime.datetime.now()) + ": Check Satellite feed for Bitcoin Node (blocksat-cli)")
    print(str(datetime.datetime.now()) + ": Check Blockstream Satellite API reader")


# ---------------------------------------------------
def telegram_bot_sendtext(bot_message):
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

    response = requests.get(send_text)

    return response.json()


# --------------------------------------------------
def send_pay(message):
    minbid = 1000  # millisatoshis
    maxbid = 40000  # millisatoshis
    bidstep = 1000  # millisatoshis
    bid = minbid
    files = {
        'bid': (None, str(bid)),
        'message': (None, message),
    }
    response = requests.post('https://api.blockstream.space/order', files=files)
    while response.status_code == 413:  # status_code: BID_TOO_SMALL (102)
        bid = bid + bidstep
        files = {
            'bid': (None, str(bid)),
            'message': (None, message),
        }
        response = requests.post('https://api.blockstream.space/order', files=files)
    if bid <= maxbid:
        data = str(response.content)
        start = data.find('payreq') + 9
        end = data.find('expires_at') - 3
        LN_invoice = data[start:end]
        LN_payment_command = ("lightning-cli pay " + LN_invoice)
        if test == 0:
            os.system(LN_payment_command)
            print(str(datetime.datetime.now()) + ": Payment executed for " + str(bid) + " millisatoshis")
        else:
            print(str(datetime.datetime.now()) + ": Payment not executed (test!=0)")
        print(str(datetime.datetime.now()) + ": LN data return: " + str(response.content))
    else:
        print(str(datetime.datetime.now()) + ": Payment not executed (bid>maxbid)")
    if test == 1:
        bid = 0
    return bid


# --------------------------------------------------

print(str(datetime.datetime.now()) + ": Starting the Bitlinq message handler - version " + str(version))
system_checks()

mqttc = mqtt.Client()

# Assign event callbacks

mqttc.on_connect = on_connect

mqttc.on_message = on_message

# Log all MQTT protocol events and exceptions in callbacks

mqttc.on_log = on_log

mqttc.username_pw_set(USERNAME, PASSWORD)

mqttc.connect(HOSTNAME, int(PORT), 60)

header = "Bitlinq message handler - PGP P2P mode -v" + str(version) + "| "
footer = " | Brought to you by www.bitlinq.space - 2020"
n_messages = 0
teller = 0
msats = 0
sent_messages = set()
n_space_messages = 0

try:
    # Listen to server
    mqttc.loop_start()

    # Main loop
    while True:
        print(str(datetime.datetime.now()) + ": V" + str(version) + " - Waiting for data.. " + str(
            len(sent_messages)) + " messages (of which " + str(
            n_space_messages) + " messages from Space) relayed so far (limit=" + str(limit_sentmessages) + ")")
        print(str(datetime.datetime.now()) + ": Total cost is: " + str(msats) + " millisatoshis. ")
        print(str(datetime.datetime.now()) + ": mode=" + mode[test])
        n_messages = len(messages)
        if n_messages != 0:
            messages2 = []
            messages2.append(messages[0])
            if timeformat == 1:
                start = 2
                stop = 12
                data = str(messages[0])
                timesent = int(data[start:stop])  # seconds since January 1, 1970
                timenow = int(time.time())
                print(str(datetime.datetime.now()) + ": Time when message was sent (Unix time):" + str(timesent))
                print(str(datetime.datetime.now()) + ": Time when message was received (Unix time):" + str(timenow))
                print(str(datetime.datetime.now()) + ": Latency of message=" + str(
                    (timenow - timesent) / 60) + " minutes")
            for i in range(1, n_messages):
                if messages[i] != messages[i - 1]:
                    messages2.append(messages[i])
            message2 = header + '\n' + '\n'.join(messages2) + '\n' + footer
            print(str(datetime.datetime.now()) + ": Message:" + message2)
            if message2 in sent_messages:
                print(str(datetime.datetime.now()) + ": Message already sent before")
            else:
                print(str(datetime.datetime.now()) + ": Gateway ID: " + gateway_ID[0])
                if gateway_ID[0] == gateway_ID_LS1:
                    print(str(
                        datetime.datetime.now()) + ": Message received from Lacuna Space LS1 payload on-board M6P satellite!!!")
                    n_space_messages = n_space_messages + 1
                msats = msats + send_pay(message2)
                text = "Message sent to Blockstream API"
                telegram_bot_sendtext(text + ": " + message2 + ", Latency of message=" + str(
                    (timenow - timesent) / 60) + " minutes, gateway_ID=" + gateway_ID[0])
                print(str(datetime.datetime.now()) + ": " + text + " (with copy to Telegram)")
                sent_messages.add(message2)
                if len(sent_messages) >= limit_sentmessages:
                    mqttc.loop_stop()
                    print(str(datetime.datetime.now()) + ": Stopped after relaying " + str(
                        limit_sentmessages) + " messages")
                    sys.exit()
            messages = []
            gateway_ID = []
        time.sleep(timestep)

except KeyboardInterrupt:
    print('\n' + "Interrupted by Keyboard (ctrl-C)")
    mqttc.loop_stop()

