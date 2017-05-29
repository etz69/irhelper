import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def vol_cmdscan(_project):
    global result

    print_header("Running cmdscan command")
    rdb = dbops.DBOps(_project.db_name)
    vp_cmdscan = {'name': 'cmdscan', 'table': 'CmdScan',
                 'output': 'db', 'type': 'default',
                 'shell': False, 'dump': False, 'parms': None}

    volatility_plugins = [vp_cmdscan]

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

    result['cmd_results'] = {'cmds': []}
    result['cmd_results']['cmds'] = load_cmd_info(_project)


def load_cmd_info(_project):

    debug("Attempting to load cmd info")
    rdb = dbops.DBOps(_project.db_name)
    query = "select Command from CmdScan"
    if rdb.table_exists('CmdScan'):
        return rdb.sqlite_query_to_json(query)


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
    #python modules/cmds/skeleton_module.py sample001.bin
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

    vol_cmdscan(my_project)
    show_json(get_result())