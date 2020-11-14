import requests
import paho.mqtt.client as mqtt
import time
import datetime
import os
import random


class BitlinqAPI:
    def __init__(self, TTN_USERNAME, TTN_PASSWORD, TTN_HOSTNAME, TTN_PORT, BOT_TOKEN, BOT_CHATID):
        # Set variables
        self.timestep = 30  # seconds
        self.limit_sentmessages = 8
        self.version = 1.054
        self.messages = []

        self.gateway_ID = []
        self.test = 0  # 1:testing option on, 0:operational mode on
        self.mode = ["Operational", "Testing (no LN payments executed)"]
        self.timeformat = 1  # 1:timeformat part of message, 0: timeformat is not part of message

        self.BOT_TOKEN = BOT_TOKEN
        self.BOT_CHATID = BOT_CHATID
        self.TTN_USERNAME = TTN_USERNAME
        self.TTN_PASSWORD = TTN_PASSWORD
        self.TTN_HOSTNAME = TTN_HOSTNAME
        self.TTN_PORT = TTN_PORT

        self.CONNECT_RESULTS = {

            0: "Connection successful",

            1: "Connection refused - incorrect protocol version",

            2: "Connection refused - invalid client identifier",

            3: "Connection refused - server unavailable",

            4: "Connection refused - bad username or password",

            5: "Connection refused - not authorised"

        }

        self.client_id = f'python-mqtt-{random.randint(0, 100)}'

    # reports connection status
    def connect_mqtt(self) -> mqtt:
        def on_connect(self,client, userdata, flags, rc):
            print(str(datetime.datetime.now()) + ": TTN - Connected with result code " + str(rc) + " : " +
                  self.CONNECT_RESULTS[
                      rc])
            if rc == 0:
                print("Connected to MQTT Broker!")
            else:
                print("Failed to connect, return code %d\n", rc)

        self.mqttc = mqtt.Client(self.client_id)
        # Assign event callbacks
        # self.mqttc.on_connect = BitlinqAPI.on_connect
        # self.mqttc.on_message = BitlinqAPI.on_message

        self.mqttc.username_pw_set(self.TTN_USERNAME, self.TTN_PASSWORD)
        self.mqttc.connect(self.TTN_HOSTNAME, int(self.TTN_PORT), 60)
        return self.mqttc

    # def on_connect(self,mqttc, mosq, obj, rc):
    #     print(str(datetime.datetime.now()) + ": TTN - Connected with result code " + str(rc) + " : " + self.CONNECT_RESULTS[
    #         rc])

    def subscribe(self,mqttc: mqtt):
        def on_message(self,client, userdata, msg):
            print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

            # print topic i.e. ttn path with the device ID at the penultimate level and 'up'

            #    print(msg.topic)

            # print the payload using any decoder specified in ttn application
            print(msg.payload)
            #    data=msg.payload.decode('ASCII')
            data = str(msg.payload)
            start = data.find('{"text":"') + 9
            stop = data.find(',"metadata":{') - 2
            self.messages.append(data[start:stop])
            print(data[start:stop])
            start = data.find('{"gtw_id":"') + 11
            stop = data.find(',"timestamp":') - 1
            self.gateway_ID.append(data[start:stop])
            print(self.gateway_ID[0])

        mqttc.subscribe('#')
        mqttc.on_message = self.mqttc.on_message

    def on_subscribe(self,mosq, obj, mid, granted_qos):
        print(str(datetime.datetime.now()) + ": TTN - Subscribed: " + str(mid) + " " + str(granted_qos))

    # def on_message(self,mqttc, obj, msg):
    #     # print topic i.e. ttn path with the device ID at the penultimate level and 'up'
    #
    #     #    print(msg.topic)
    #
    #     # print the payload using any decoder specified in ttn application
    #     print(msg.payload)
    #     #    data=msg.payload.decode('ASCII')
    #     data = str(msg.payload)
    #     start = data.find('{"text":"') + 9
    #     stop = data.find(',"metadata":{') - 2
    #     self.messages.append(data[start:stop])
    #     print(data[start:stop])
    #     start = data.find('{"gtw_id":"') + 11
    #     stop = data.find(',"timestamp":') - 1
    #     self.gateway_ID.append(data[start:stop])
    #     print(self.gateway_ID[0])

    def on_publish(self,mosq, obj, mid):
        print(str(datetime.datetime.now()) + ": TTN - mid: " + str(mid))

    def on_log(self,mqttc, obj, level, buf):
        print(str(datetime.datetime.now()) + ": TTN - message:" + str(buf))

        print(str(datetime.datetime.now()) + ": TTN - userdata:" + str(obj))

    # ---------------------------------------------------
    def system_checks(self):
        print(str(datetime.datetime.now()) + ": Check Bitcoin Node (bitcoind)")
        print(str(datetime.datetime.now()) + ": Check Lightning Network (LN) node (c-lightning)")
        print(str(datetime.datetime.now()) + ": Check Satellite feed for Bitcoin Node (blocksat-cli)")
        print(str(datetime.datetime.now()) + ": Check Blockstream Satellite API reader")

    # ---------------------------------------------------
    def telegram_bot_sendtext(self,bot_message):
        send_text = 'https://api.telegram.org/bot' + self.BOT_TOKEN + '/sendMessage?chat_id=' + self.BOT_CHATID + '&parse_mode=Markdown&text=' + bot_message

        response = requests.get(send_text)

        return response.json()

    # --------------------------------------------------
    def send_pay(self,message):
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
            if self.test == 0:
                os.system(LN_payment_command)
                print(str(datetime.datetime.now()) + ": Payment executed for " + str(bid) + " millisatoshis")
            else:
                print(str(datetime.datetime.now()) + ": Payment not executed (test!=0)")
            print(str(datetime.datetime.now()) + ": LN data return: " + str(response.content))
        else:
            print(str(datetime.datetime.now()) + ": Payment not executed (bid>maxbid)")
        if self.test == 1:
            bid = 0
        return bid

    def repack_messages(self, messages):
        counter = 0
        index = set()
        payloads = {}
        base64_payload = ''
        counter = 0
        for row in data:
            # with 23 messages expected
            # print(ord(row['text'][0:1]) - 65 - 23)
            # with 12 messages expected
            # print(ord(row['text'][0:1]) - 65 - 12)
            message_number = ord(row['text'][0:1])
            if message_number not in payloads.keys():
                payloads[message_number] = {row['text'][1:]}
                # print(payloads)

            # if ord(row['text'][0:1]) - 65 - 12 >= counter:
            #   print(counter)
            #   base64+=row['text'][1:-1]
            #   counter+=1
            # #print(row['text'][1:-1])
            # # payloads["index"] = ord(row['text'][0:1]) - 65 - 12
            # # payloads["payload"] = row['text'][1:-1]
            # payloads.update([('index', ord(row['text'][0:1]) - 65 - 12), ('payload', row['text'][1:-1])])
            # index.add(ord(row['text'][0:1]) - 65 - 12)

        # sorted(list, key=..., reverse=...)
        # print(sorted(index))

        # print(payloads.keys())
        # print(payloads.values())
        # print("\n")

        # for key, payload in payloads.items():
        #   print(payload)
        # Creates a sorted dictionary (sorted by key)
        from collections import OrderedDict
        payloads_sorted = OrderedDict(sorted(payloads.items()))
        for key, values in payloads_sorted.items():
            print("%s: %s" % (key, list(values)[0]))
            base64_payload += list(values)[0]

        print(base64_payload)
        print("\n")
