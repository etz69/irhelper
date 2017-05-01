import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}


def vol_malfind_extended(_project):
    global result

    print_header("Running malfind_extended command")

    rc, result = execute_volatility_plugin(plugin_type="default",
                                            plugin_name="malfind",
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

    mlf = MafindTool()
    if mlf.test():
        debug("MLF ok!")

    sections = []
    line_number = 0
    cmd_out = result['cmd_results'].split('\n')
    for n in cmd_out:
        debug(n)
        if n.startswith("Process:"):
            sections.append(line_number)

        line_number += 1

    #print sections
    #print len(sections)
    running = True
    results = []
    process_list = {}

    while running:
        for idx, elem in enumerate(sections):

            if idx == (len(sections)-1):
                running = False
                break;
            thiselem = elem
            nextelem = sections[(idx + 1) % len(sections)]
            data = mlf.get_section(thiselem,cmd_out,nextelem)
            pid, name, address = mlf.serialize_data(data)

            asm = mlf.get_asm(data)
            asm_string = ''.join(asm).replace(",","")

            matches = re.findall('[A-Z]{3}', asm_string, re.DOTALL)

            process_list['asm'] = ':'.join(matches)
            process_list['mem_loc'] = address
            process_list['pid'] = pid
            process_list['name'] = name
            process_list['mz'] = mlf.check_mz(mlf.get_hex_string(data)[0])
            process_list['entropy'] = calculate_shanon_string(process_list['asm'])

            #print process_list['pid'],process_list['mem_loc'],process_list['mz'],process_list['asm']
            #choice = raw_input("Good or Bad? ")
            choice = "good"
            process_list['classification'] = choice

            results.append(process_list)

            process_list = {}

    result['cmd_results'] = results


def get_result():
    return result


def show_json(in_response):
    ##Function to test json output
    print(json.dumps(in_response, sort_keys=False, indent=4))


if __name__ == "__main__":
    #
    print("Python version: %s\n " % sys.version)

    DB_NAME = "results.db"

    set_debug(True)

    ##Get module parameters
    image = sys.argv[1]
    profile = sys.argv[2]

    ##Call the actual command
    current_wd = sys.path[0]
    my_project = Project(current_wd)
    my_project.set_volatility_profile(profile)
    my_project.init_db(DB_NAME)
    my_project.set_image_name(image)

    vol_malfind_extended(my_project)
    show_json(get_result())