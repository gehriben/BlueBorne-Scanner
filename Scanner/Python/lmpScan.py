import subprocess
import sql

lmpversions =	{
  "0": 1.0,
  "1": 1.1,
  "2": 1.2,
  "3": 2.0,
  "4": 2.1,
  "5": 3.0,
  "6": 4.0,
  "7": 4.1,
  "8": 4.2,
  "9": 5.0,
  "10": 5.1
}

def findBluetoothVersion(dst, SQL_ACTIVE):
    try:
        info = subprocess.check_output(['hcitool', 'info', dst])
        findIndex = info.index("(0x")
        if findIndex > 0:
            version = info[findIndex+3]
            version = lmpversions[str(version)]
            print ("Die verwendete Bluetooth Version ist: %s" % (version))
            if(SQL_ACTIVE):
                sql.updateBluetoothVersion(dst,version)
        else:
            print("Keine Bluetooth Version gefunden.")
    except:
       print("Keine Bluetooth Version gefunden.") 