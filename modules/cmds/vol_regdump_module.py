import subprocess
import json
import sqlite3
import sys
import os
import re
import ConfigParser

sys.path.append(sys.path[0]+"/../../")
from modules.db.ops import *
from modules.utils import samparser

result = {'status': True, 'message': '', 'cmd_results': ''}
GLOBALS = {}


def vol_regdump(image_file, globals_in):

    global GLOBALS
    GLOBALS = globals_in

    print_header("Executing vol_regdump command")


    ##Construct the required command
    ##First we need to find if the SAM is in memory

    cmd_array = []
    cmd_array.append("vol.py")
    if "_cache" in GLOBALS:
        cmd_array.append('--cache')
    cmd_array.append('--profile='+GLOBALS['_VOLATILITY_PROFILE'])
    if "_KDBG" in GLOBALS:
        cmd_array.append('--kdbg='+GLOBALS['_KDBG'])
    cmd_array.append('-f')
    cmd_array.append(image_file)
    #The command and the output
    cmd_array.append('hivelist')
    cmd_array.append('--output=sqlite')
    cmd_array.append('--output-file=results.db')

    debug(cmd_array)

    ##Run the constructed command

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
        result['message'] = "hivelist command failed!"
        err(result['message'])

    reg_info = get_sam_offset()
    ##now lets dump the registry from mem
    ##Construct the required command
    ##First we need to find if the SAM is in memory

    cmd_array = []
    cmd_array.append("vol.py")
    if "_cache" in GLOBALS:
        cmd_array.append('--cache')
    cmd_array.append('--profile='+GLOBALS['_VOLATILITY_PROFILE'])
    if "_KDBG" in GLOBALS:
        cmd_array.append('--kdbg='+GLOBALS['_KDBG'])
    cmd_array.append('-f')
    cmd_array.append(image_file)
    #The command and the output
    cmd_array.append('dumpregistry')
    cmd_array.append('-o')
    cmd_array.append(reg_info['offset'])
    cmd_array.append('-D')
    cmd_array.append(GLOBALS['DUMP_DIR'])

    debug(cmd_array)

    ##Run the constructed command

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
        result['message'] = "dumpregistry command failed!"
        err(result['message'])

    debug(cmd_out)


    matchObj = re.findall(r":\sregistry.*.reg", str(cmd_out), flags=0)
    reg_file = ""
    try:
        reg_file = matchObj[0].strip(": ")
        debug(matchObj[0].strip(": "))
    except Exception,e:
        result['message'] = "Could not extract SAM registry"

    if reg_file != "":
        j = samparser.main(GLOBALS['DUMP_DIR']+reg_file,"json")

        #debug(j)
        debug("Run samparser")
        result['cmd_results'] = j



def get_sam_offset():

### Get the SAM offset if it exists

    con = sqlite3.connect('results.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('select virtual,name from hivelist where name like "%Config\SAM%";')
    rows = cur.fetchone()
    data = {}
    data['offset'] = '0x{:x}'.format(int(rows['virtual']))
    data['name'] = rows['name']

    con.close()
    return data


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys = False, indent = 4))


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
    vol_regdump(image, GLOBALS)
    show_json(get_result())