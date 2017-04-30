import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def skeleton_module(_project):
    global result

    print_header("Running skeleton command example")

    debug("Project root: [%s]" % _project.get_root())
    debug("Plugins dir: [%s]" % _project.plugins_dir)
    debug("Report export dir: [%s]" % _project.report_export_location)
    debug("Pyplot flag: [%s]" % _project.pyplot_flag)

    rc, result = execute_volatility_plugin(plugin_type="default",
                                            plugin_name="pslist",
                                            output="stdout",
                                            result=result,
                                            project=_project,
                                            shell=False,
                                            dump=False,
                                            plugin_parms=None)
    if result['status']:
        debug("CMD completed")
    else:
        err(result['message'])


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))


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

    skeleton_module(my_project)
    show_json(get_result())