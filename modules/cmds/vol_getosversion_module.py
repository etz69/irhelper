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

import json
import sqlite3
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def vol_getosversion(_project):
    global result

    print_header("Attempting to gather OS version info")

    #####Test AREA
    #####Test AREA

    ##We need to use shell as we need to escape reg key chars
    plugin_parms = "-K 'Microsoft\Windows NT\CurrentVersion'"

    rc, result = execute_volatility_plugin(plugin_type="default",
                                            plugin_name="printkey",
                                            output="db",
                                            result=result,
                                            project=_project,
                                            shell=True,
                                            dump=False,
                                            plugin_parms=plugin_parms)
    if result['status']:
        debug("CMD completed")
    else:
        err(result['message'])


    ##Run custom systeminfo
    rc, result = execute_volatility_plugin(plugin_type="contrib",
                                            plugin_name="systeminfo",
                                            output="db",
                                            result=result,
                                            project=_project,
                                            shell=True,
                                            dump=False,
                                            plugin_parms=None)

    if result['status']:
        debug("CMD completed")
        result['cmd_results'] = extract_version_info()
    else:
        err("Will not extract version info")
        #err(result['message'])



def extract_version_info():

    con = sqlite3.connect('results.db')
    cur = con.cursor()
    cur.execute('SELECT Valname,ValData FROM Printkey WHERE Valname!="-"')
    rows = cur.fetchall()
    data = {}
    for row in rows:
        data[row[0]] = row[1]

    try:
        cur.execute('SELECT summary from systeminfo where'
                    ' source like "ComputerName%"')
        row = cur.fetchone()
        data['compname'] = row[0]
        cur.execute('SELECT summary from systeminfo where'
                    ' source like "Domain%"')
        row = cur.fetchone()
        data['domain'] = row[0]

    except Exception as e:
        err(e)

    con.close()

    return data


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))


if __name__ == "__main__":
    #python modules/cmds/vol_getosversion_module.py sample001.bin Win7SP1x64
    print("Python version: %s\n " % sys.version)
    DB_NAME = "results.db"

    set_debug(True)

    ##Get module parameters
    image = sys.argv[1]
    profile = sys.argv[2]

    ##Call the actual command
    current_wd = sys.path[0]
    my_project = Project(current_wd)
    my_project.init_db(DB_NAME)
    my_project.set_volatility_profile(profile)
    my_project.set_image_name(image)

    vol_getosversion(my_project)
    show_json(get_result())

