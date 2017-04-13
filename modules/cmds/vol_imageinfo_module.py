import subprocess
import json
import sqlite3
import ConfigParser
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': ''}
GLOBALS = {}


def vol_imageinfo(image_file, globals_in):

    global GLOBALS
    GLOBALS = globals_in

    print_header("Gathering image initial information")

    cmd_array = []
    cmd_array.append("vol.py")
    if GLOBALS:
        if GLOBALS['_cache']:
            cmd_array.append('--cache')
    cmd_array.append('-f')
    cmd_array.append(image_file)
    #The command and the output
    cmd_array.append('imageinfo')
    cmd_array.append('--output=sqlite')
    cmd_array.append('--output-file=results.db')

    debug(cmd_array)

    _proc = subprocess.Popen(cmd_array, stdout=subprocess.PIPE)
    debug("Child process pid: %s"%_proc.pid)

    rc = _proc.poll()
    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "imageinfo command failed!"
        err(result['message'])

    result['cmd_results'] = get_imageinfo()


def get_imageinfo():

    con = sqlite3.connect('results.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('select * from imageinfo')
    rows = cur.fetchone()

    data = {}
    for key in rows.keys():
        _value = rows[key]
        if key == "KDBG":
            _value = format(int(_value), '#04x')
        if key == "DTB":
            _value = format(int(_value), '#04x')

        data[key] = _value

    con.close()

    return data


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))


if __name__ == "__main__":
    print("Python version: %s\n " %sys.version)

    ##When entering via main the paths change
    GLOBALS = {}
    set_debug(True)

    ##Load settings.py
    settings = sys.path[0]+"/../../settings.py"
    config = ConfigParser.ConfigParser()

    config.read(settings)
    GLOBALS['PLUGIN_DIR'] = config.get('Directories', 'plugins').strip("'")
    GLOBALS['DUMP_DIR'] = config.get('Directories', 'dump').strip("'")

    ##Get module parameters
    action = sys.argv[1]
    image = sys.argv[2]
    profile = sys.argv[3]

    ##Load required GLOBALS
    GLOBALS['_VOLATILITY_PROFILE'] = profile
    GLOBALS['_cache'] = True
    for key in GLOBALS:
        debug("%s: %s" %(key,GLOBALS[key]))

    ##Call the actual command
    vol_imageinfo(image, GLOBALS)
    show_json(get_result())