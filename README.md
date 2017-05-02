# irhelper
A play POC tool for initial quick analysis of memory images for fun and learning!

[![Code Climate](https://codeclimate.com/github/etz69/irhelper/badges/gpa.svg)](https://codeclimate.com/github/etz69/irhelper)

Quick install
------------
External prerequisites:

* volatility (Mandatory)
* exiftool (Optional)
* Clamav (Optional)

```
git clone https://github.com/etz69/irhelper.git
cd irhelper
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt

vi settings.py
Edit all locations with the full path of your irhelper installation

And Play !
python irhelper.py --initdb --debug templates/report.html sample001.bin



```

Note: if the matplotlib is not working disable in the settings.py file




```
python irhelper.py -h

usage: irhelper.py [-h] [-p [PROFILE]] [--cache] [--debug] [--initdb] [--hash]
                   [-v]
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
                        Volatility profile
  --cache               Enable cache
  --debug               Run in debug
  --initdb              Initialise local DB
  --hash                Generate hashes
  -v, --version         show program's version number and exit

  ```

Features
--------
This is the initial alpha version of IRHelper so please bear with us if the code
is not up to your standards or sth is not working very well !

* Retrieve all target image information
* Extract users and relevant timestamps from SAM registry dump
* Apply rules on running processes. Currently we check the running number of instances,
naming tricks, parent process
* Dump all memory processes and retrieve as much information both from PEB and exiftool output
* Enhanced process list with PEB info (where available)
* Suspicious processes. PIDs which exist in psxview, malfind and apihooks
* Malfind output processor which identified MZ headers or trampoline style sections
* Network connections list
* Network connection graph based on matplotlib

Documentation is currently updated to describe all the above features.
