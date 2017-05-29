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


def vol_regdump(_project):
    global result

    print_header("Executing vol_regdump command")

    ##Construct the required command
    ##First we need to find if the SAM is in memory
    rdb = dbops.DBOps(_project.db_name)


    ##Note this is stdout so we need to store for later
    vp_dumpreg_out = ""
    vp_hivelist = {'name': 'hivelist', 'table': 'HiveList',
                 'output': 'db', 'type': 'default',
                 'shell': False, 'dump': False, 'parms': None}

    volatility_plugins = [vp_hivelist]

    for plugin in volatility_plugins:

        if not rdb.table_exists(plugin['table']):
            rc, result = execute_volatility_plugin(plugin_type=plugin['type'],
                                                   plugin_name=plugin['name'],
                                                   output=plugin['output'],
                                                   result=result,
                                                   project=_project,
                                                   shell=plugin['shell'],
                                                   dump=plugin['dump'],
                                                   plugin_parms=plugin['parms'])

            if result['status']:
                debug("CMD completed %s" % plugin['name'])
            else:
                err(result['message'])

    reg_info = get_sam_offset(_project)
    ##now lets dump the registry from mem
    ##Construct the required command
    ##First we need to find if the SAM is in memory
    debug(reg_info)

    if 'offset' in reg_info:
        parms = "-o "+reg_info['offset']

    plugin = {'name': 'dumpregistry', 'table': 'None',
                  'output': 'stdout', 'type': 'default',
                  'shell': True, 'dump': True, 'parms': parms}


    rc, result = execute_volatility_plugin(plugin_type=plugin['type'],
                                           plugin_name=plugin['name'],
                                           output=plugin['output'],
                                           result=result,
                                           project=_project,
                                           shell=plugin['shell'],
                                           dump=plugin['dump'],
                                           plugin_parms=plugin['parms'])

    if result['status']:
        debug("CMD completed %s" % plugin['name'])
        vp_dumpreg_out = result['cmd_results']
    else:
        err(result['message'])

    debug(result['cmd_results'])

    reg_file = ""

    if vp_dumpreg_out != "":
        matchObj = re.findall(r":\sregistry.*.reg", str(vp_dumpreg_out), flags=0)
        reg_file = ""
        try:
            reg_file = matchObj[0].strip(": ")
            debug(matchObj[0].strip(": "))
        except Exception as e:
            result['message'] = "Could not extract SAM registry"

    if reg_file != "":
        try:
            j = samparser.main(_project.dump_dir+reg_file, "json")

            debug("Run samparser")
            result['cmd_results'] = j
        except Exception as e:
            err("Could not read registry")
    else:
        err("Could not run samparser")


def get_sam_offset(_project):

### Get the SAM offset if it exists
    data = dict()
    con = sqlite3.connect('results.db')
    rdb = dbops.DBOps(_project.db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if rdb.table_exists("HiveList"):
        cur.execute('select virtual,name from hivelist where name like "%Config\SAM%";')
        rows = cur.fetchone()
        data['offset'] = '0x{:x}'.format(int(rows['virtual']))
        data['name'] = rows['name']

        con.close()
    else:
        err("Hivelist table does not exist")
    return data


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    try:
        print(json.dumps(in_response, sort_keys=False, indent=4))
    except TypeError as e:
        print(json.dumps({"error": "Error with decoding JSON"},
                         sort_keys=False, indent=4))

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