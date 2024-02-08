Installation
=============================

Es wird Python in der Version 2.7 benötigt. <br />
Nachfolgend sind die erforderlichen Bibliotheken für die Installation dokumentiert.

===============

**Python Dependencies:**

    pip2 packages: pybluez, pwn, scapy
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn scapy
    - sudo pip install progressbar2

**Ubertooth (V2018-12-R1):**

    - sudo apt-get install cmake libusb-1.0-0-dev make gcc g++ libbluetooth-dev pkg-config libpcap-dev python-numpy python-pyside python-  qt4
    - wget https://github.com/greatscottgadgets/libbtbb/archive/2018-12-R1.tar.gz -O libbtbb-2018-12-R1.tar.gz
      tar -xf libbtbb-2018-12-R1.tar.gz
      cd libbtbb-2018-12-R1
      mkdir build
      cd build
      cmake ..
      make
      sudo make install
    - wget https://github.com/greatscottgadgets/ubertooth/releases/download/2018-12-R1/ubertooth-2018-12-R1.tar.xz
      tar xf ubertooth-2018-12-R1.tar.xz
      cd ubertooth-2018-12-R1/host
      mkdir build
      cd build
      cmake ..
      make
      sudo make install
    

Scanner ausführen:
=============================

    sudo python scanner.py [Parameter]

| Parameter            | Erforderlich  | Beschreibung                                                                                                             |
|----------------------|---------------|--------------------------------------------------------------------------------------------------------------------------|
| [BADDR]              | ja            | Die Bluetooth Adresse des eigenen Bluetooth Adapters (ohne weitere Parameter wird der normale Scan gestartet).           |
| [BADDR] -u [TIME]    | nein          | Startet den Scanner im Ubertooth-Modus. Die UAP wird durch den Ubertooth berechnet.                                      |
| [BADDR] -u -b [TIME] | nein          | Startet den Scanner im Ubertooth-Modus. Die UAP wird durch Bruteforce errechnet.                                         |
| [BADDR] -sql         | nein          | Startet den automatisierten Scan (ohne weitere Parameter werden sowohl normaler Scan als auch Ubertooth-Scan gestartet). |
| [BADDR] -sql -n      | nein          | Startet den automatisierten Modus für den normalen Scan.                                                                 |
| [BADDR] -sql -u      | nein          | Startet den automatisierten Modus für den Ubertooth-Scan. Die UAP wird standardmässig durch den Ubertooth berechnet.     |

**Parameter für [TIME]**

| Parameter | Scanzeit für LAP                       | Scanzeit UAP          |
|-----------|----------------------------------------|-----------------------|
| -s        | 20 Sekunden für alle gefundenen Geräte | 10 Sekunden pro Gerät |
| -m        | 30 Sekunden für alle gefundenen Geräte | 20 Sekunden pro Gerät |
| -l        | 40 Sekunden für alle gefundenen Geräte | 40 Sekunden pro Gerät |

*Hinweis: Für den automatiserten scan wird eine sql Datenbank benötigt die in der sql.py Datei entsprechend konfiguriert werden muss.* 

