import re
import subprocess
import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *
from modules.utils import samparser


result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}
###TODO: Remove sqlite3
import sqlite3


def vol_regdump(project):

    print_header("Executing vol_regdump command")


    ##Construct the required command
    ##First we need to find if the SAM is in memory
    debug(project.dump_dir)

    cmd_array = []
    cmd_array.append("vol.py")
    cmd_array.append('--cache')
    cmd_array.append('--profile='+project.get_volatility_profile())
    if project.image_kdgb != "":
        cmd_array.append('--kdbg='+project.image_kdgb)
    cmd_array.append('-f')
    cmd_array.append(project.image_name)
    #The command and the output
    cmd_array.append('hivelist')
    cmd_array.append('--output=sqlite')
    cmd_array.append('--output-file='+project.db_name)

    debug(cmd_array)

    ##Run the constructed command

    rc = subprocess.call(cmd_array)

    if rc == 0:
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
    cmd_array.append('--cache')
    cmd_array.append('--profile='+project.get_volatility_profile())
    if project.image_kdgb != "":
        cmd_array.append('--kdbg='+project.image_kdgb)

    cmd_array.append('-f')
    cmd_array.append(project.image_name)
    #The command and the output
    cmd_array.append('dumpregistry')
    cmd_array.append('-o')
    cmd_array.append(reg_info['offset'])
    cmd_array.append('-D')
    cmd_array.append(project.dump_dir)

    debug(cmd_array)

    ##Run the constructed command
    cmd_out = ""
    reg_file = ""
    try:
        rc = subprocess.check_output(cmd_array)
        result['status'] = True
        cmd_out = rc
    except subprocess.CalledProcessError as e:
        result['status'] = False
        result['message'] = "Exception: dumpregistry command failed!"
        err(result['message'])

    debug(cmd_out)

    if cmd_out != "":
        matchObj = re.findall(r":\sregistry.*.reg", str(cmd_out), flags=0)
        reg_file = ""
        try:
            reg_file = matchObj[0].strip(": ")
            debug(matchObj[0].strip(": "))
        except Exception as e:
            result['message'] = "Could not extract SAM registry"

    if reg_file != "":
        j = samparser.main(project.dump_dir+reg_file,"json")

        debug("Run samparser")
        result['cmd_results'] = j
    else:
        err("Could not run samparser")



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
    print(json.dumps(in_response, sort_keys=False, indent=4))

if __name__ == "__main__":
    #python modules/cmds/vol_regdump_module.py sample001.raw Win7SP1x64
    print("Python version: %s\n " %sys.version)
    DB_NAME = "results.db"

    set_debug(True)

    ##Get module parameters
    image = sys.argv[1]
    profile = sys.argv[2]

    ##Call the actual command
    current_wd = sys.path[0]
    project = Project(current_wd)
    project.init_db(DB_NAME)
    project.set_volatility_profile(profile)
    project.set_image_name(image)

    vol_regdump(project)
    show_json(get_result())