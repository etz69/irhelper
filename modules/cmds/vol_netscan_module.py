###Gather network related information
# TCP Connections plugins (WinXP and 2003 only)
#connections, connscan

# All protocols (WinXP and 2003 only)
#sockets, sockscan

# All protocols (Windows Vista, Windows 2008 Server and Windows 7)
#netscan


import subprocess
import sys
import json
import ConfigParser

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': ''}
GLOBALS = {}

def vol_netscan(image_file, globals_in):
    global GLOBALS
    GLOBALS = globals_in

    print_header("Gathering network information")

    debug("Checking compatible plugins")
    _profile = GLOBALS['_VOLATILITY_PROFILE']
    debug("Profile detected: %s" %_profile)

    if _profile == "":
        result['status'] = False
        result['message'] = "Empty profile!"
        return result

    if _profile.startswith('WinXP') or _profile.startswith('Win2003'):
        volatility_plugin = "sockscan"
        debug("Running sockscan")
    else:
        volatility_plugin = "netscan"
        debug("Running netscan")


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
    cmd_array.append(volatility_plugin)
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
        result['message'] = "network plugin failed!"
        err(result['message'])

    ###Get network interface information from memory (custom plugin)
    #ndispktscan experimental


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
    vol_netscan(image, GLOBALS)
    show_json(get_result())