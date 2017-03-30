# irhelper
A play POC tool for initial quick analysis of memory images for fun and learning!

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
