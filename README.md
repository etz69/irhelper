# irhelper
A play POC tool for initial quick analysis of memory images for fun and learning!

Quick install
---
External prerequsites:

* volatility
* exiftool

```
git clone https://github.com/etz69/irhelper.git
cd irhelper
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt

vi settings.py
Edit all locations with the full path of your irhelper installation

Note: if the matplotlib is not working disable in the settings.py file

And Play !
python irhelper.py --initdb --debug templates/report.html sample001.bin



```



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
