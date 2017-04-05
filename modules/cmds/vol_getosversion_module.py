# #$ vol.py printkey -K "Microsoft\Windows NT\CurrentVersion"
# Values:
# REG_SZ        CurrentVersion  : (S) 6.1
# REG_SZ        CurrentBuild    : (S) 7601
# REG_SZ        SoftwareType    : (S) System
# REG_SZ        CurrentType     : (S) Multiprocessor Free
# REG_DWORD     InstallDate     : (S) 1473414645
# REG_SZ        RegisteredOrganization : (S)  Group
# REG_SZ        RegisteredOwner : (S)  User
# REG_SZ        SystemRoot      : (S) C:\WINDOWS
# REG_SZ        InstallationType : (S) Client
# REG_SZ        EditionID       : (S) Enterprise
# REG_SZ        ProductName     : (S) Windows 7 Enterprise
# REG_SZ        ProductId       : (S) 00392-918-5000002-85981
# REG_BINARY    DigitalProductId : (S)
# REG_SZ        CurrentBuildNumber : (S) 7601
# REG_SZ        BuildLab        : (S) 7601.win7sp1_ldr.160408-2045
# REG_SZ        BuildLabEx      : (S) 7601.23418.amd64fre.win7sp1_ldr.160408-2045
# REG_SZ        BuildGUID       : (S) 091be891-23de-4d6d-b020-1e7aceb08a39
# REG_SZ        CSDBuildNumber  : (S) 1130
# REG_SZ        PathName        : (S) C:\WINDOWS
# REG_SZ        CSDVersion      : (S) Service Pack 1
# REG_SZ        CM_DSLID        : (S) JMP:JMP0002B
#sqlite
#id|Registry|KeyName|KeyStability|LastWrite|Subkeys|SubkeyStability|ValType|ValName|ValStability|ValData
#Valname CurrentVersion

##Module description
#Atempts to extract target OS information by reading registry key values

##Pitfalls
#Related registry keys might not be present in captured memory

import subprocess
import json
import sqlite3
import sys
import ConfigParser

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *


result = {'status': True, 'message': '', 'cmd_results': ''}
GLOBALS = {}

def vol_getosversion(image_file, globals_in):

    global GLOBALS
    GLOBALS = globals_in

    print_header("Attempting to gather OS version info")

    #####Test AREA


    #####Test AREA

    ##We need to use shell as we need to escape reg key chars

    cmd = "vol.py --cache -f "+image_file+\
          " --profile="+GLOBALS['_VOLATILITY_PROFILE']+\
          " printkey -K 'Microsoft\Windows NT\CurrentVersion' " \
          " --output-file=results.db --output=sqlite"

    debug(cmd)
    _proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    debug("Child process pid: %s"%_proc.pid)

    rc = _proc.poll()

    while rc == None:
        cmd_out =_proc.stdout.read()
        rc = _proc.poll()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "printkey command failed!"
        err(result['message'])


    ##Run custom systeminfo
    cmd = "vol.py --plugins="+GLOBALS['PLUGIN_DIR']+ \
          " --cache -f "+image_file+" " \
          " --profile="+GLOBALS['_VOLATILITY_PROFILE'] + \
          " systeminfo" +\
          " --output-file=results.db --output=sqlite"

    debug(cmd)
    _proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    _proc.wait()

    if _proc.returncode == 0:
        result['status'] = True
    else:
        result['status'] = False
        result['message'] = "systeminfo plugin failed!"

    result['cmd_results'] = extract_version_info()


def extract_version_info():

    con = sqlite3.connect('results.db')
    cur = con.cursor()
    cur.execute('select Valname,ValData from Printkey where Valname!="-"')
    rows = cur.fetchall()
    data = {}
    for row in rows:
        data[row[0]] = row[1]

    try:
        cur.execute('select summary from systeminfo where'
                    ' source like "ComputerName%"')
        row = cur.fetchone()
        data['compname'] = row[0]
        cur.execute('select summary from systeminfo where'
                    ' source like "Domain%"')
        row = cur.fetchone()
        data['domain'] = row[0]

    except Exception, e:
        err(e)

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
    vol_getosversion(image, GLOBALS)
    show_json(get_result())


