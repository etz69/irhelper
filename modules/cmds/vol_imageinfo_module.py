import json
import sqlite3
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}

def vol_imageinfo(_project):
    global result

    print_header("Gathering image initial information")

    ##Run custom systeminfo
    rc, result = execute_volatility_plugin(plugin_type="default",
                                            plugin_name="imageinfo",
                                            output="db",
                                            result=result,
                                            project=_project,
                                            shell=False,
                                            dump=False,
                                            plugin_parms=None)

    if result['status']:
        debug("CMD completed")
        result['cmd_results'] = get_image_info(_project)
    else:
        err(result['message'])
        err("Imageinfo could not complete. Exiting")


def get_image_info(_project):

    con = sqlite3.connect(_project.db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('SELECT * FROM imageinfo')
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
    #python modules/cmds/vol_imageinfo_module.py sample001.bin
    print("Python version: %s\n " % sys.version)

    DB_NAME = "results.db"

    set_debug(True)

    ##Get module parameters
    image = sys.argv[1]

    ##Call the actual command
    current_wd = sys.path[0]
    my_project = Project(current_wd)
    my_project.init_db(DB_NAME)
    my_project.set_image_name(image)

    vol_imageinfo(my_project)
    show_json(get_result())