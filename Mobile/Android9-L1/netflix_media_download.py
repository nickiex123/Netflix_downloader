#! /usr/bin/python
import frida
import sys
import base64
import gzip
import json
import pycurl
import cbor2
import string
import random
import sys
from humanize import naturalsize
import time

START_TIME = None
random_str=""
def progress(download_t, download_d, upload_t, upload_d):
    if int(download_t) == 0:
        return
    global START_TIME
    if START_TIME is None:
        START_TIME = time.time()
    duration = time.time() - START_TIME + 1
    speed = download_d / duration
    speed_s = naturalsize(speed, binary=True)
    speed_s += '/s'
    if int(download_d) == 0:
        download_d == 0.01
    p = '\t[*] Download %s/%s (%.2f%%) %s %s\r' % (naturalsize(download_d, binary=True),
                                    naturalsize(download_t, binary=True),
                                    download_d / download_t, speed_s, ' ' * 10)
    sys.stderr.write(p)
    sys.stderr.flush()

def rand_string():
    number_of_strings = 5
    length_of_string = 8
    for x in range(number_of_strings):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length_of_string))
    
def video_download(data):
    global random_str
    data=data['video_tracks'][0]
    data=data['streams']
    data=data[len(data)-4]
    data=data['urls'][0]
    url=data['url']
    print("[*] start video download now!")
    filename=random_str+"_video"+".avi"
    with open(filename, 'wb') as f:
        cl = pycurl.Curl()
        cl.setopt(cl.URL, url)
        cl.setopt(cl.WRITEDATA, f)
        cl.setopt(cl.NOPROGRESS, False)
        cl.setopt(cl.PROGRESSFUNCTION, progress)
        cl.perform()
        cl.close()

def audio_download(data):
    global random_str
    data=data['audio_tracks'][0]
    data=data['streams']
    data=data[len(data)-1]
    data=data['urls'][0]
    url=data['url']
    print("[*] start audio download now!")
    filename=random_str+"_audio"+".avi"
    with open(filename, 'wb') as f:
        cl = pycurl.Curl()
        cl.setopt(cl.URL, url)
        cl.setopt(cl.WRITEDATA, f)
        cl.setopt(cl.NOPROGRESS, False)
        cl.setopt(cl.PROGRESSFUNCTION, progress)
        cl.perform()
        cl.close()
        
def text_download(data):
    global random_str
    data=data['timedtexttracks'][0]
    data=data['ttDownloadables']
    data=data['webvtt-lssdh-ios8']
    data=data['downloadUrls']
    data=json.dumps(data)
    data=data.split(': "')
    data=data[1]
    data=data.split('"')
    url=data[0]
    print("[*] start text download now!")
    filename=random_str+"_text"+".txt"
    with open(filename, 'wb') as f:
        cl = pycurl.Curl()
        cl.setopt(cl.URL, url)
        cl.setopt(cl.WRITEDATA, f)
        cl.setopt(cl.NOPROGRESS, False)
        cl.setopt(cl.PROGRESSFUNCTION, progress)
        cl.perform()
        cl.close()
    
def onGenericDecrypt(message, data):
    global random_str
    if (message['payload'] == "plaintext"):
        array = [c for c in data]
        data = cbor2.loads(bytearray(array))
        try:
            data=gzip.decompress(data[62])
            data=json.loads(data)
            data=data['result'][0]
            random_str=rand_string()
            video_download(data)
            print()
            audio_download(data)
            print()
            text_download(data)
            print()
        except:
            pass
    
attach_process = 'android.hardware.drm@1.1-service.widevine'

device = frida.get_usb_device(timeout=10)
session = device.attach(attach_process)
print("[+] Attached to " + attach_process)

# OEMCrypto_GenericDecrypt (_oecc25) JS
print("[+] Processing script _oecc25")

genericDecrypt_data = """
Interceptor.attach(Module.getExportByName('libwvhidl.so', '_oecc25'), {
    onEnter: function (args) {
        this.plaintext = args[5];
        this.len = args[2].toInt32();
    },
    onLeave: function (retval) {
        send("plaintext",this.plaintext.readByteArray(this.len));
    }
});
"""
script_genericDecrypt = session.create_script(genericDecrypt_data)
script_genericDecrypt.on('message', onGenericDecrypt)
print("\t[+] Loading script")
script_genericDecrypt.load()
print("\t[+] Script loaded successfully")

sys.stdin.read()
session.detach()
print("[+] Detached")