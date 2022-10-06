#! /usr/bin/python

import frida
import sys
import time

def isKeybox(data):
    return (data[0x78:0x7c] == [107, 98, 111, 120]) # "kbox" magic number

def printDeviceKey(keybox):
    deviceKey = [ str(hex(c)) for c in keybox[0x20:0x30]]
    print('Device key in hex: ' + ' '.join(deviceKey))

def onMunmap(message, data):
    if (message['type'] == "send"):
        raw = [c for c in data]
        if (isKeybox(raw)):
            tmp = str(int(round(time.time() * 1000)))
            fileName = "./keybox_" + tmp + ".raw"
            fd = open(fileName, 'wb')
            print("[+] Writing keybox file: " + fileName)
            fd.write(data)
            fd.close()
            printDeviceKey(raw)

mediadrm = 'mediaserver'

device = frida.get_usb_device(timeout=10)
session = device.attach(mediadrm)
print("[+] Attached to " + mediadrm)

# munmap JS
print("[+] Processing script munmap")

munmap_data = """
Interceptor.attach(Module.getExportByName('libwvdrmengine.so', 'munmap'), {
    onEnter: function (args) {
        this.len = args[1].toInt32();
        if (this.len == 0x80) {
	        send("addr", args[0].readByteArray(this.len));
        }
    },
    onLeave: function (retval) {
    }
});
"""
script_munmap = session.create_script(munmap_data)
script_munmap.on('message', onMunmap)
print("\t[+] Loading script")
script_munmap.load()
print("\t[+] Script loaded successfully")

sys.stdin.read()
session.detach()
print("[+] Detached")

