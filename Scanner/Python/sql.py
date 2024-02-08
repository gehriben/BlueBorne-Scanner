import mysql.connector

mydb = None

def initDatabase():
	global mydb
  	mydb = mysql.connector.connect(
		host="[MYSQL IP]",
		user="[USER]",
		passwd="[PASSWORD]",
		database="[DB NAME]"
    )

def selectAll():
    mycursor = mydb.cursor(buffered=True)
    mycursor.execute("SELECT * FROM device")
    myresult = mycursor.fetchall()

def selectByMac(addr):
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "SELECT * FROM device WHERE mac = %s"
        val = (addr,)

        mycursor.execute(sql, val)
        myresult = mycursor.fetchone()

        return myresult[0]
    except Exception as e:
        print("SQL Error in selectByMac!")
        print(e)

def insertDevice(name, addr, scantype):
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "INSERT INTO device (mac, attackstatus, name, scantype) VALUES (%s, %s, %s, %s)"
        val = (addr, 'none', name, scantype)

        mycursor.execute(sql, val)
        mydb.commit()

        return mycursor.lastrowid
    except Exception as e:
        print("SQL Error in insertDevice!")
        print(e)

def updateDeviceMac(newAddr, oldAddr):  
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "UPDATE device SET mac = %s WHERE mac = %s"
        val = (newAddr, oldAddr)

        mycursor.execute(sql, val)
        mydb.commit()
    except Exception as e:
        print("SQL Error in updateDeviceMace!")
        print(e)
    
def updateBluetoothVersion(addr,version):
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "UPDATE device SET bluetooth = %s WHERE mac = %s"
        val = (version,addr)

        mycursor.execute(sql, val)
        mydb.commit()
    except Exception as e:
        print("SQL Error in updateBluetoothVersion!")
        print(e)

def updateDeviceType(addr, typ):    
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "UPDATE device SET devicetype = %s WHERE mac = %s"
        val = (typ,addr)

        mycursor.execute(sql, val)
        mydb.commit()
    except Exception as e:
        print("SQL Error in updateDeviceType!")
        print(e)

def updateAttackstate(addr, attackStatus):
    try:
        mycursor = mydb.cursor(buffered=True)

        sql = "UPDATE device SET attackstatus = %s WHERE mac = %s"
        val = (attackStatus, addr)

        mycursor.execute(sql, val)
        mydb.commit()
    except Exception as e:
        print("SQL Error in updateStatusAndDeviceType!")
        print(e)

def updateDeviceState(addr, state):
    try:
        mycursor = mydb.cursor(buffered=True)

        addr = str("%") + addr

        sql = "UPDATE device SET state = %s WHERE mac LIKE %s"
        val = (state, addr)

        mycursor.execute(sql, val)
        mydb.commit()
    except Exception as e:
        print("SQL Error in updateDeviceState!")
        print(e)

#Return the attackStatus of one device!
def checkDeviceStatus(addr):
    mycursor = mydb.cursor(buffered=True)

    sql = "SELECT attackstatus FROM device WHERE mac = %s"
    val = (addr,)

    mycursor.execute(sql, val)
    mydb.commit()

    myresult = mycursor.fetchone()

    return myresult[0]


def selectByUAPLAP(addr):
    #Prepare addr to look like 00:00:XX:XX:XX:XX
    addr = addr[6:17]
    addr = str("%") + addr

    mycursor = mydb.cursor(buffered=True)
    
    sql = "SELECT * FROM device WHERE mac LIKE %s"
    val = (addr,)

    mycursor.execute(sql, val)
    myresult = mycursor.fetchone()

    return myresult[0]

def checkDeviceStatusUAPLAP(addr):
    #Prepare addr to look like 00:00:XX:XX:XX:XX
    addr = addr[6:17]
    addr = str("%") + addr

    mycursor = mydb.cursor(buffered=True)
    
    sql = "SELECT attackstatus FROM device WHERE mac LIKE %s"
    val = (addr,)

    mycursor.execute(sql, val)
    myresult = mycursor.fetchone()

    return myresult[0]

def addTimestamp(id):
        mycursor = mydb.cursor(buffered=True)

        sql = "INSERT INTO timestamp (deviceId) VALUES (%s)"
        val = (id,)

        mycursor.execute(sql, val)
        mydb.commit()
