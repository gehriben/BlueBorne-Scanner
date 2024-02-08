import sys
import mysql.connector
import matplotlib.pyplot as plt

mydb = None

DAY_START = 2
DAY_END = 5

def initDatabase():
    global mydb
    mydb = mysql.connector.connect(
		host="160.85.156.210",
		user="root",
		passwd="root",
		database="BLUEBORNE"
    )
    print("finished")

def executeSQLStatement(sqlString, values):
    mycursor = mydb.cursor(buffered=True)

    mycursor.execute(sqlString, values)
    myresult = mycursor.fetchone()

    return myresult[0]

def getDataPerDay(day, sqlString):
    dayData = []
    for i in range(24):
        dayData.append(getDataPerHour(sqlString, (day,i,day,i+1)))

    return dayData

def averageOfAllDays(allDays):
    averageDay = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    dayAmountPerHour = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    for x in range(24):
        for y in range(len(allDays)):
            averageDay[x] += allDays[y][x]
            if (allDays[y][x] > 0):
                dayAmountPerHour[x] += 1

    for i in range(24):
        averageDay[i] =  averageDay[i] / dayAmountPerHour[x]

    return averageDay

def createPlotForAmountScannedDevices():
    sql = "SELECT COUNT(DISTINCT t.id) " +\
        "FROM (SELECT d.id, d.mac, d.name, tp.tstamp FROM device AS d " +\
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s %s%' AND '2019-12-%s %s%' ORDER BY tp.tstamp) AS t"

    names = ['0 Uhr', '1 Uhr', '2 Uhr', '3 Uhr', '4 Uhr', '5 Uhr', '6 Uhr', '7 Uhr', '8 Uhr', '9 Uhr', '10 Uhr', '11 Uhr', '12 Uhr','13 Uhr','14 Uhr','15 Uhr','16 Uhr','17 Uhr','18 Uhr', '19 Uhr', '20 Uhr', '21 Uhr', '22 Uhr', '23 Uhr']
    #names = ['0 Uhr', '2 Uhr', '4 Uhr', '6 Uhr', '8 Uhr', '10 Uhr', '12 Uhr','14 Uhr','16 Uhr','18 Uhr', '20 Uhr', '22 Uhr']

    allDays = []
    for i in range(DAY_START, DAY_END+1):
        allDays.append(getDataPerDay(i, sql))

    averageOfAllDays_ = averageOfAllDays(allDays)
    plt.bar(names, averageOfAllDays_)
    plt.ylabel('Anzahl Geräte')
    plt.xlabel('Zeit')

    for x in range(24):
        plt.annotate(str(averageOfAllDays_[x]), xy=(x-0.2,averageOfAllDays_[x]+0.125))

    plt.show()

def createPlotForAmountVulnerableDevices():
    sqlVulnerable = "SELECT COUNT(DISTINCT t.id, t.name, t.attackstatus) " + \
        "FROM (SELECT d.id, d.mac, d.name, d.attackstatus, tp.tstamp FROM device AS d " + \
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s%' AND '2019-12-%s%' ORDER BY tp.tstamp) AS t " +\
        "WHERE t.attackstatus = 'Vulnerable'"

    sqlPatched = "SELECT COUNT(DISTINCT t.id, t.name, t.attackstatus) " + \
        "FROM (SELECT d.id, d.mac, d.name, d.attackstatus, tp.tstamp FROM device AS d " + \
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s%' AND '2019-12-%s%' ORDER BY tp.tstamp) AS t " +\
        "WHERE t.attackstatus = 'Patched' "

    amountPatchedDevices = executeSQLStatement(sqlPatched, (DAY_START, DAY_END))
    amountVulnerableDevices = executeSQLStatement(sqlVulnerable, (DAY_START, DAY_END))

    plt.bar(["Patched", "Vulnerable"], [amountPatchedDevices, amountVulnerableDevices])
    plt.xlabel('Anzahl Verwundbare Geräte')

    plt.annotate(str(amountPatchedDevices), xy=(0-0.2,amountPatchedDevices+0.125))
    plt.annotate(str(amountVulnerableDevices), xy=(1-0.2,amountVulnerableDevices+0.125))

    plt.show()

def createPlotForAmountLMPVersions():
    sql = "SELECT COUNT(DISTINCT t.lmp), t.lmp " + \
        "FROM (SELECT d.lmp, tp.tstamp FROM device AS d " + \
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s%' AND '2019-12-%s%') AS t" 

    amountLMPVersions = executeSQLStatement(sql, (DAY_START, DAY_END))

    LMPVersionsName = []
    LMPVersionsValue = []
    for x in range(len(amountLMPVersions)):
        LMPVersionsName.append(amountLMPVersions[0])
        LMPVersionsValue.append(amountLMPVersions[1])

    plt.bar(LMPVersionsName, LMPVersionsValue)
    plt.xlabel('Anzahl verschiedener LMP Versions')

    plt.show()

def createPlotForAmountDevicetype():
    sqlAndroid = "SELECT COUNT(DISTINCT t.id)" + \
        "FROM (SELECT d.id, d.name, tp.tstamp FROM device AS d " + \
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s%' AND '2019-12-%s%' AND d.state = 'Device successfully tested' ) AS t" 

    sqlOther = "SELECT COUNT(DISTINCT t.id)" + \
        "FROM (SELECT d.id, d.name, tp.tstamp FROM device AS d " + \
        "JOIN timestamp tp ON tp.deviceId = d.id " +\
        "WHERE tstamp BETWEEN '2019-12-%s%' AND '2019-12-%s%' AND d.state = 'Invalid continuation state received.' ) AS t" 

    amountAndroidDevices = executeSQLStatement(sqlAndroid, (DAY_START, DAY_END))
    amountOtherDevices = executeSQLStatement(sqlOther, (DAY_START, DAY_END))

    plt.bar(["Android", "Andere"], [amountAndroidDevices, amountOtherDevices])
    plt.xlabel('Anzahl verschiedener Systemtypen')

    plt.show()


def main():
    print("Start")
    initDatabase()

    createPlotForAmountScannedDevices()
    createPlotForAmountVulnerableDevices()


if __name__ == '__main__':
    main(*sys.argv[1:])