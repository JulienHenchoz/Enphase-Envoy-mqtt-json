#!/usr/bin/python3
# 
# This version reads json from Envoy then publishes the json to mqtt broker
#
# Version 1.0 1st September 2021 - Initial release
# Version 1.1 7th November 2021 - Include date/time to output for checking 
# Version 1.2 6th April 2022 - tidy up some comments
# Version 1.3 7th April 2022 - converted to work as a Home Assistant Addon
# 
#Version 1.4 17th July 2023 - converted to work with V7 firmware by https://github.com/helderfmf
#
# Ian Mills
# vk2him@gmail.com
#


import json
import urllib3
import requests
from requests.auth import HTTPDigestAuth
import threading
import pprint
from datetime import datetime
import time
import xml.etree.ElementTree as ET
#disable warnings of self signed certificate https
urllib3.disable_warnings()
import paho.mqtt.client as mqtt
client = mqtt.Client()
pp = pprint.PrettyPrinter()
import xml.etree.ElementTree as ET
import hashlib
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(connect=3, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)


with open("data/options.json", "r") as f:
    option_dict = json.load(f)
# print(option_dict["x"])

##

now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
#print ("date =", dt_string)

#
##### Settings Start here
#
# I use the Home Assistant Mosquito broker add-on but you can use an external one if needed
# python

MQTT_HOST = option_dict["MQTT_HOST"]  # Note - if issues connecting, use FQDN for broker IP instead of hassio.local
MQTT_PORT = option_dict["MQTT_PORT"]
MQTT_TOPIC = option_dict["MQTT_TOPIC"]  # Note - if you change this topic, you'll need to also change the value_templates in configuration.yaml
MQTT_USER = option_dict["MQTT_USER"]     # As described in the Documentation for the HA Mosquito broker add-on, the MQTT user/password are the user setup for mqtt
MQTT_PASSWORD = option_dict["MQTT_PASSWORD"]    # If you use an external broker, use those details instead
ENVOY_HOST = option_dict["ENVOY_HOST"]  # ** Enter envoy-s IP. Note - use FQDN and not envoy.local if issues connecting
ENVOY_USER= option_dict["ENVOY_USER"]
ENVOY_USER_PASS= option_dict["ENVOY_USER_PASS"]
USE_FREEDS= option_dict["USE_FREEDS"]
BATTERY_INSTALLED= option_dict["BATTERY_INSTALLED"]
DEBUG= option_dict["DEBUG"]
MQTT_TOPIC_FREEDS = "Inverter/GridWatts"
####  End Settings - no changes after this line

#Password generator
userName = b'installer'
DEFAULT_REALM = b'enphaseenergy.com'
gSerialNumber = None
tokenfile = 'data/token.txt'
####  End Settings - no changes after this line

def log(message):
    dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(message)

#json validator
def is_json_valid(json_data):
    if isinstance(json_data, bytes):
        json_data = json_data.decode('utf-8', errors='replace')
    try:
        json.loads(json_data)
    except ValueError as e:
        return False
    return True

# Get info
connection_success = False

while not connection_success:
    try:
        log('Trying to connect to Envoy at' + ENVOY_HOST + 'to get info')
        url_info ='http://%s/info' % ENVOY_HOST
        response_info = session.get(url_info, verify=False)
        if response_info.status_code != 200:
            log('Failed connect to Envoy to get info got ' + response_info + 'Verify URL' + url_info )
            time.sleep(30)
        else:
            root = ET.fromstring(response_info.content)
            serialNumber = [child.text for child in root.iter('sn')]
            version = [child.text for child in root.iter('software')]
            connection_success = True
            log("Connection to Envoy at" + ENVOY_HOST + "successful")

        if len(serialNumber) != 0:
            serialNumber = serialNumber[0]
            log('Serial number:' + serialNumber)
        else:
            log('Cannot decode serial number did not got valid XML for <sn> from ' + url_info)
            log('Response content:' + response_info.content)
            time.sleep(30)

        if len(version) != 0:
            if version[0].count('D7.') == 1:
                log('Detected FW version 7')
                envoy_version=7
            elif version[0].count('D8.') == 1:
                log('Detected Firmware version D8')
                envoy_version=8
            elif version[0].count('R5.') == 1:
                log('Detected Firmware version R5')
                envoy_version=5
            elif version[0].count('D5.') == 1:
                log('Detected Firmware version D5')
                envoy_version=5
            else:
                log('Cannot match firmware version, got ' + version)
                time.sleep(30)
        else:
            log('Cannot decode firmware version, did not got valid XML for <software> from ' + url_info)
            log('Response content:' + response_info.content)
            time.sleep(30)

        if USE_FREEDS:
            log('FREEDS is active, using topic:' + MQTT_TOPIC_FREEDS)
        else:
            log('FREEDS is inactive')
    except Exception as e:
        log('Exception connecting to Envoy:')
        print(e)
        log('Retrying in 30 seconds...')
        connection_success = False
        time.sleep(30)

#Token generator
def token_gen(token):
    if token is None or token=='':
        log('Generating new token')
        data = {'user[email]': ENVOY_USER, 'user[password]': ENVOY_USER_PASS}
        if DEBUG: log( 'Token data:' + data)
        response = requests.post('https://enlighten.enphaseenergy.com/login/login.json?', data=data)
        if response.status_code != 200:
            log('Failed connect to https://enlighten.enphaseenergy.com/login/login.json? to generate token part 1 got' + response, ' using this info' + data )
            time.sleep(20)
        else:
            if DEBUG: log( 'Token response' + response.text)
            response_data = json.loads(response.text)
            data = {'session_id': response_data['session_id'], 'serial_num': serialNumber, 'username': ENVOY_USER}
            response = requests.post('https://entrez.enphaseenergy.com/tokens', json=data)
            if response.status_code != 200:
                log('Failed connect to https://entrez.enphaseenergy.com/tokens to generate token part 2 got' + response, ' using this info' + data )
            else:
                log('Token generated' + response.text)
                with open(tokenfile, 'w') as f:
                    f.write(response.text)
                return response.text
    else:
        return token

#cache token
if envoy_version != 5:
    if not os.path.exists(tokenfile):
        with open(tokenfile, 'w') as f:
            f.write('')

    with open(tokenfile, 'r') as f:
        try:
            ENVOY_TOKEN = f.read()
            if ENVOY_TOKEN:
                log( 'Read token from file' + tokenfile,': '+ ENVOY_TOKEN)
                pass
            else:
                log( 'No token in file:' + tokenfile)
                ENVOY_TOKEN=token_gen(None)
                pass
        except Exception as e:
            print(e)

# The callback for when the client receives a CONNACK response from the server.
    # Subscribing after on_connect() means that if the connection is lost
    # the subscription will be renewed when reconnecting.
    #The parameter rc is an integer giving the return code:
    #0: Success
    #1: Refused – unacceptable protocol version
    #2: Refused – identifier rejected
    #3: Refused – server unavailable
    #4: Refused – bad user name or password (MQTT v3.1 broker only)
    #5: Refused – not authorised (MQTT v3.1 broker only

def on_connect(client, userdata, flags, rc):
    """
    Handle connections (or failures) to the broker.
    This is called after the client has received a CONNACK message
    from the broker in response to calling connect().
    The parameter rc is an integer giving the return code:
    0: Success
    1: Refused . unacceptable protocol version
    2: Refused . identifier rejected
    3: Refused . server unavailable
    4: Refused . bad user name or password (MQTT v3.1 broker only)
    5: Refused . not authorised (MQTT v3.1 broker only)
    """
    if rc == 0:
        log("Connected to %s:%s" % (MQTT_HOST, MQTT_PORT))
        # Subscribe to our incoming topic
        client.subscribe(MQTT_TOPIC)
        log('Subscribed to MQTT_TOPIC:' + "{0}".format(MQTT_TOPIC))
    elif rc == 1:
        log(" Connection refused - unacceptable protocol version")
    elif rc == 2:
        log(" Connection refused - identifier rejected")
    elif rc == 3:
        log(" Connection refused - server unavailable")
    elif rc == 4:
        log(" Connection refused - bad user name or password")
    elif rc == 5:
        log(" Connection refused - not authorised")
    else:
        log(" Connection failed - result code %d" % (rc))

def on_publish(client, userdata, mid) :
    print("mid: {0}".format(str(mid)))

def on_disconnect(client, userdata, rc) :
    print("Disconnect returned:")
    print("client: {0}".format(str(client)))
    print("userdata: {0}".format(str(userdata)))
    print("result: {0}".format(str(rc)))

def on_log(client, userdata, level, buf) :
    print("{0}".format(buf))

client               = mqtt.Client()
client.on_connect    = on_connect
#client.on_publish    = on_publish
client.on_disconnect = on_disconnect
# Uncomment to enable debug messages
client.on_log       = on_log
client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
if DEBUG: log( 'Will wait for mqtt connect')
wait: client.connect(MQTT_HOST,int(MQTT_PORT), 30)
if DEBUG: log( 'Finished waiting for mqtt connect')
wait: client.loop_start()

## Generation of Envoy password based on serial number, copy from https://github.com/sarnau/EnphaseEnergy/passwordCalc.py
## Credits to Markus Fritze https://github.com/sarnau/EnphaseEnergy
def emupwGetPasswdForSn(serialNumber, userName, realm):
    if serialNumber == None or userName == None:
        return None
    if realm == None:
        realm = DEFAULT_REALM
    return hashlib.md5(b'[e]' + userName + b'@' + realm + b'#' + serialNumber + b' EnPhAsE eNeRgY ').hexdigest()

def emupwGetPasswd(userName,realm):
    global gSerialNumber
    if gSerialNumber:
        return emupwGetPasswdForSn(gSerialNumber, userName, realm);
    return None;

def emupwGetPublicPasswd(serialNumber, userName, realm, expiryTimestamp=0):
    if expiryTimestamp==0:
        expiryTimestamp = int(time.time());
    return hashlib.md5(userName + b'@' + realm + b'#' + serialNumber + b'%d' % expiryTimestamp).hexdigest()

def emupwGetMobilePasswd(serialNumber,userName,realm=None):
    global gSerialNumber
    gSerialNumber = serialNumber
    digest = emupwGetPasswdForSn(serialNumber,userName,realm)
    countZero = digest.count('0')
    countOne = digest.count('1')
    password = ''
    for cc in digest[::-1][:8]:
        if countZero == 3 or countZero == 6 or countZero == 9:
            countZero = countZero -1
        if countZero > 20:
            countZero = 20
        if countZero < 0:
            countZero = 0
        if countOne == 9 or countOne == 15:
            countOne = countOne -1
        if countOne > 26:
            countOne = 26
        if countOne < 0:
            countOne = 0
        if cc == '0':
            password += chr(ord('f') + countZero)
            countZero = countZero - 1
        elif cc == '1':
            password += chr(ord('@') + countOne)
            countOne = countOne -1
        else:
            password += cc
    return password

def scrape_stream_production():
    global ENVOY_TOKEN
    ENVOY_TOKEN=token_gen(ENVOY_TOKEN)
    while True:
        try:
            print("Polling production data")
            url = 'http://%s/production.json' % ENVOY_HOST
            headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
            stream = session.get(url, timeout=5, verify=False, headers=headers)
            if stream.status_code == 401:
                log('Failed to autenticate' + stream, ' generating new token')
                ENVOY_TOKEN=token_gen(None)
                headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
                stream = session.get(url, timeout=5, verify=False, headers=headers)
            elif stream.status_code != 200:
                log('Failed connect to Envoy got ' + stream)
                time.sleep(20)
            else:
                if is_json_valid(stream.content):
                    json_string = json.dumps(stream.json())
                    client.publish(topic= MQTT_TOPIC , payload= json_string, qos=0 )
                    if USE_FREEDS:
                        json_string_freeds = json.dumps(round(stream.json()['consumption'][0]['wNow']))
                        client.publish(topic= MQTT_TOPIC_FREEDS , payload= json_string_freeds, qos=0 )
                    time.sleep(3)
                else:
                    log( 'Invalid Json Response:')
                    print(stream.content)
                    time.sleep(20)
        except requests.exceptions.RequestException as e:
            log( ' Exception fetching stream data: %s' % e)
            time.sleep(20)

def scrape_stream_livedata():
    global ENVOY_TOKEN
    ENVOY_TOKEN=token_gen(ENVOY_TOKEN)
    activate_json={"enable": 1}
    while True:
        print("Polling livedata")
        try:
            url = 'https://%s/ivp/livedata/status' % ENVOY_HOST
            headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
            stream = session.get(url, timeout=5, verify=False, headers=headers)
            if stream.status_code == 401:
                log('Failed to autenticate' + stream, ' generating new token')
                ENVOY_TOKEN=token_gen(None)
                headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
                stream = session.get(url, timeout=5, verify=False, headers=headers)
            elif stream.status_code != 200:
                log('Failed connect to Envoy got ' + stream)
                time.sleep(20)
            elif is_json_valid(stream.content):
                if stream.json()['connection']['sc_stream'] == 'disabled':
                    url_activate='https://%s/ivp/livedata/stream' % ENVOY_HOST
                    log( 'Stream is not active, trying to enable')
                    response_activate=requests.post(url_activate, verify=False, headers=headers, json=activate_json)
                    if is_json_valid(response_activate.content):
                        if response_activate.json()['sc_stream']=='enabled':
                            stream = session.get(url, stream=True, timeout=5, verify=False, headers=headers)
                            log( 'Success, stream is active now')
                        else:
                            log( 'Failed to activate stream ' + response_activate.content)
                            time.sleep(20)
                    else:
                        log( 'Invalid Json Response:' + response_activate.content)
                        time.sleep(20)
                else:
                    json_string = json.dumps(stream.json())
                    #log( 'Json Response:' + json_string)
                    client.publish(topic= MQTT_TOPIC , payload= json_string, qos=0 )
                    if USE_FREEDS:
                        json_string_freeds = json.dumps(round(stream.json()["meters"]["grid"]["agg_p_mw"]*0.001))
                        client.publish(topic= MQTT_TOPIC_FREEDS , payload= json_string_freeds, qos=0 )
                    time.sleep(3)
            elif not is_json_valid(stream.content):
                log( 'Invalid Json Response:')
                print(stream.content)
                time.sleep(20)

        except requests.exceptions.RequestException as e:
            log( ' Exception fetching stream data: %s' % e)
            time.sleep(20)

def scrape_stream_meters():
    global ENVOY_TOKEN
    ENVOY_TOKEN=token_gen(ENVOY_TOKEN)
    while True:
        print("Polling meters data")
        try:
            url = 'https://%s/ivp/meters/readings' % ENVOY_HOST
            if DEBUG: log( 'Url:' + url)
            headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
            if DEBUG: log( 'headers:' + json.dumps(headers))
            stream = session.get(url, timeout=5, verify=False, headers=headers)
            # Dump response headers
            log( 'Response headers:' + json.dumps(dict(stream.headers)))
            if DEBUG:
                log( 'stream:')
                print(stream.content)
            if stream.status_code == 401:
                log('Failed to autenticate' + stream, ' generating new token')
                ENVOY_TOKEN=token_gen(None)
                headers = {"Authorization": "Bearer " + ENVOY_TOKEN}
                if DEBUG: log( 'headers after 401:' + headers)
                stream = session.get(url, timeout=5, verify=False, headers=headers)
                if DEBUG: log( 'stream after 401:' + stream.content)
            elif stream.status_code != 200:
                log('Failed connect to Envoy got ' + stream)
                time.sleep(20)
                if DEBUG:
                    log( 'stream after != 200:')
                    print(stream.content)
            else:
                if is_json_valid(stream.content):
                    json_string = json.dumps(stream.json())
                    if DEBUG: log( 'Json Response:' + json_string)
                    client.publish(topic= MQTT_TOPIC , payload= json_string, qos=0 )
                    if USE_FREEDS:
                        json_string_freeds = json.dumps(round(stream.json()[1]["activePower"]))
                        if DEBUG: log( 'Json freeds:' + stream.json()[1]["activePower"])
                        client.publish(topic= MQTT_TOPIC_FREEDS , payload= json_string_freeds, qos=0 )
                else:
                    log( 'Invalid Json Response:')
                    print(stream.content)
                    time.sleep(20)
        except requests.exceptions.RequestException as e:
            log( ' Exception fetching stream data: %s' % e)
            time.sleep(20)
        time.sleep(3)

def scrape_stream():
    serial = serialNumber.encode("utf-8")
    ENVOY_PASSWORD=emupwGetMobilePasswd(serial, userName)
    log( 'Envoy password is' + ENVOY_PASSWORD)
    if DEBUG: log( 'Username:',userName.decode())
    auth = HTTPDigestAuth(userName.decode(), ENVOY_PASSWORD)
    if DEBUG: log( 'auth:',auth)
    marker = b'data: '
    while True:
        try:
            url = 'http://%s/stream/meter' % ENVOY_HOST
            if DEBUG: log( 'Url:' + url)
            stream = session.get(url, auth=auth, stream=True, timeout=5)
#            if DEBUG: log( 'stream:' + stream.content)
            for line in stream.iter_lines():
#                if DEBUG: log( 'Line:' + line)
                if line.startswith(marker):
                    if DEBUG: log( 'Line marker:' + line)
                    data = json.loads(line.replace(marker, b''))
#                    if DEBUG: log( 'Data:' + data)
                    json_string = json.dumps(data)
                    client.publish(topic= MQTT_TOPIC , payload= json_string, qos=0 )
        except requests.exceptions.RequestException as e:
            log( ' Exception fetching stream data: %s' % e)
        time.sleep(20)

def main():
    #Use url https://envoy.local/production.json
    #stream_thread = threading.Thread(target=scrape_stream_production)

    #Use this for batteries url https://envoy.local/ivp/livedata/status
    #stream_thread = threading.Thread(target=scrape_stream_livedata)

    #Use url http://envoy.local/ivp/meters/reading
    #stream_thread = threading.Thread(target=scrape_stream_meters)
    print(envoy_version)
    if envoy_version == 5:
        stream_thread = threading.Thread(target=scrape_stream)
        stream_thread.start()
    elif BATTERY_INSTALLED:
        stream_thread = threading.Thread(target=scrape_stream_livedata)
        stream_thread.start()        
    elif envoy_version == 8:
        stream_thread = threading.Thread(target=scrape_stream_meters)
        stream_thread.start()
    elif envoy_version == 7:
        stream_thread = threading.Thread(target=scrape_stream_meters)
        stream_thread.start()
    else:
        log('Don''t know what version to use, will not start')

if __name__ == '__main__':
    main()
