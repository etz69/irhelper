(venv)fsck:irhelper dxl$ python irhelper.py -h

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