# IRhelper
A play POC tool for initial quick analysis of memory images for fun and learning!
A great way to learn:

* Python :)
* Volatility (either scripting or at some point you will need to write a plugin !)
* Memory forensics

[![Code Climate](https://codeclimate.com/github/etz69/irhelper/badges/gpa.svg)](https://codeclimate.com/github/etz69/irhelper)
[![Documentation Status](http://readthedocs.org/projects/irhelper/badge/?version=latest)](http://irhelper.readthedocs.io/en/latest/?badge=latest)

IRhelper Report
------------
This is how the end report looks like:

[![IRhelper Report](https://github.com/etz69/irhelper/raw/master/docs/artifacts/ScreenShotReport.png)


Quick install
------------
External prerequisites:

* volatility (Mandatory)
* exiftool (Optional but highly recommended)
* Clamav (Not yet implemented)

Note: Mac users might get an error related to LOCALE. Run the below on your shell.

```
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
```


```
git clone https://github.com/etz69/irhelper.git
cd irhelper
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt

vi settings.py
* Edit all locations with the full path of your irhelper installation
* Add any API Keys required (VT, C1fApp)


And Play !
python irhelper.py --hash --vt --initdb --debug templates/report.html sample001.bin



```

* Note1: If the matplotlib is not working disable in the settings.py file
* Note2: Disable your AV for the directory "irhelper/dump"




```
cmd>python irhelper.py -h

usage: irhelper.py [-h] [-p [PROFILE]] [-r [RISK]] [--cache] [--debug]
                   [--initdb] [--hash] [--vt] [--osint] [-v]
                   reportTemplate memoryImageFile

  ;)( ;
 :----:
C|====|
 |    |
 `----

The IR helper python tool!

positional arguments:
  reportTemplate        Report template to use
  memoryImageFile       The memory image file you want to analyse

optional arguments:
  -h, --help            show this help message and exit
  -p [PROFILE], --profile [PROFILE]
                        Volatility profile (Optional)
  -r [RISK], --risk [RISK]
                        Risk level to show processes (default 2)
  --cache               Enable cache
  --debug               Run in debug
  --initdb              Initialise local DB
  --hash                Generate hashes
  --vt                  Check VirusTotal for suspicious hash (API KEY
                        required)
  --osint               Check C1fApp for OSINT of ip/domain (API KEY required)
  -v, --version         show program's version number and exit

  ```

Features
--------
This is the initial alpha version of IRHelper so please bear with us if the code
is not up to your standards or sth is not working very well !

* Retrieve all target image information
* Extract users and relevant timestamps from SAM registry dump
* Apply rules on running processes. Currently we check the running number of instances,
naming tricks, parent process utilising more dynamic methods such as Jaro–Winkler distance
* Dump all memory processes and retrieve as much information both from mem and with exiftool
* Calculate entropy of memory dump images and ASM suspicious snippets
* Enhanced process list with PEB info (where available)
* Suspicious processes. PIDs which exist in psxview, malfind and apihooks
* Malfind output processor which identifies MZ headers or trampoline style sections
* Hollowfind plugin
* Network connections list
* Network connection graph based on matplotlib
* Command line history
* VirusTotal check of suspicious hashes

Documentation is currently updated to describe all the above features.
