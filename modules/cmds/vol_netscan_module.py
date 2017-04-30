###Gather network related information
# TCP Connections plugins (WinXP and 2003 only)
#connections, connscan

# All protocols (WinXP and 2003 only)
#sockets, sockscan

# All protocols (Windows Vista, Windows 2008 Server and Windows 7)
#netscan

import json
import sys

sys.path.append(sys.path[0]+"/../../")
from modules.utils.helper import *
from modules.db import DBops as dbops

result = {'status': True, 'message': '', 'cmd_results': '', 'errors': []}

import sqlite3

##Graphing
import networkx as nx

##TODO: Not all processes are displayed !!!! Also use scan for processes as well


def vol_netscan(_project):
    global result
    print_header("Gathering network information")

    ###Testing area

    ###Testing area

    debug("Checking compatible plugins")
    _profile = _project.get_volatility_profile()
    debug("Profile detected: %s" % _profile)

    if _profile == "":
        result['status'] = False
        result['message'] = "Empty profile!"
        return result

    ##todo:add connscan
    if _profile.startswith('WinXP') or _profile.startswith('Win2003'):
        volatility_plugin = "sockscan"
        _net_table = "SockScan"
        debug("Running sockscan")
    else:
        volatility_plugin = "netscan"
        _net_table = "Netscan"
        debug("Running netscan")

    rdb = dbops.DBOps(_project.db_name)

    if not rdb.table_exists(_net_table):
        debug("Table for %s not found running now" %volatility_plugin)


        rc, result = execute_volatility_plugin(plugin_type="default",
                                                plugin_name=volatility_plugin,
                                                output="db",
                                                result=result,
                                                project=_project,
                                                shell=False,
                                                dump=False,
                                                plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    ##Run Connscan also
    if _profile.startswith('WinXP') or _profile.startswith('Win2003'):
        volatility_plugin = "connscan"
        _net_table = "ConnScan"
        if not rdb.table_exists(_net_table):
            debug("Table for %s not found running now" %volatility_plugin)


            rc, result = execute_volatility_plugin(plugin_type="default",
                                                    plugin_name=volatility_plugin,
                                                    output="db",
                                                    result=result,
                                                    project=_project,
                                                    shell=False,
                                                    dump=False,
                                                    plugin_parms=None)

            if result['status']:
                debug("CMD completed")
            else:
                err(result['message'])



    ###TODO: This should be moved in pslist module or check for table
    print_header("Executing vol_pslist...")


    if not rdb.table_exists('PSList'):
        debug("Table for pslist not found running now")
        rc, result = execute_volatility_plugin(plugin_type="default",
                                            plugin_name="pslist",
                                            output="db",
                                            result=result,
                                            project=_project,
                                            shell=False,
                                            dump=False,
                                            plugin_parms=None)

        if result['status']:
            debug("CMD completed")
        else:
            err(result['message'])

    ##Draw graph
    normalize_network_info(_project)
    ###Get network interface information from memory (custom plugin)
    #ndispktscan experimental
    extended_network_info = []
    for entry in result['cmd_results']['network']:
        flag, type = valid_ip(entry['destination'].split(":")[0])
        entry['address_type'] = type
        entry['ip_address'] = entry['destination'].split(":")[0]
        extended_network_info.append(entry.copy())

    result['cmd_results']['network'] = extended_network_info


def load_processes(_project):

    debug("Attempting to load process info")

    con = sqlite3.connect(_project.get_root()+'results.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('select process,pid,process_fullname from psinfo2')

    rows = cur.fetchall()
    plist = {}

    for rs in rows:
        ps = {}
        ps['pid'] = rs['pid']
        ps['process_fullname'] = rs['process_fullname']
        ps['process_name'] = rs['process']
        if ps['process_fullname'] == "NoPEB":
            ps['process_fullname'] = rs['process']

        plist[ps['pid']] = ps.copy()

    return plist


def normalize_network_info(_project):

    print_header("Network data normalization")
    global result
    _table = ""
    net_info = []
    plist = load_processes(_project)

    rdb = dbops.DBOps(_project.get_root()+"results.db")
    if rdb.table_exists('Netscan'):
        debug("Netscan table exists")
        _table = "Netscan"
    if rdb.table_exists('SockScan'):
        _table = "SockScan"
        debug("SockScan table exists")


    if _table != "":
        con = sqlite3.connect('results.db')
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute('SELECT * from '+_table+'')

        rows = cur.fetchall()
        if _table == "SockScan":
            debug("Loading data from SockScan")
            for rs in rows:
                flag, type = valid_ip(rs[6])
                #debug("%s [%s,%s]" %(rs[6], flag, type))
                if flag:
                    net_info.append((rs[2], rs[6]))
            ##check for connscan as well
            if rdb.table_exists('ConnScan'):
                debug("Loading data from ConnScan")
                _table = "ConnScan"
                cur.execute('select pid,remoteaddress from '+_table+'')
                rows = cur.fetchall()
                for rs in rows:
                    flag, type = valid_ip(rs[1].split(":")[0])
                    if flag:
                        net_info.append((rs[0], rs[1]))


        if _table == "Netscan":
            for rs in rows:
                flag, type = valid_ip(rs[4].split(":")[0])
                if flag:
                    net_info.append((rs[6], rs[4]))

        result['cmd_results'] = {'network': []}
        cleaned = list(set(net_info))
        rdict = {}

        for e in cleaned:

            for p in plist:
                if str(p) == str(e[0]):

                    rdict[str(p)] = plist[p]

        f = []
        #result['cmd_results']['network'].append(n.copy())

        for entry in cleaned:
            if str(entry[0]) in rdict:
                n = {'name': rdict[str(entry[0])]['process_name'] ,'pid': entry[0], 'destination':entry[1]}
                f.append(n.copy())
                result['cmd_results']['network'].append(n.copy())

            else:
                n = {'name': entry[0] ,'pid': entry[0], 'destination':entry[1]}
                result['cmd_results']['network'].append(n.copy())

    else:
        err("No network table found")
        result['cmd_results']['network'] = []

    net_info_new = []

    for conn in net_info:
        new_tuple = ()
        if str(conn[0]) in rdict:
            new_tuple = (rdict[conn[0]]['process_name'], conn[1])
            net_info_new.append(new_tuple)
        else:
            net_info_new.append(conn)

    generate_network_graph(net_info_new, _project)


def generate_network_graph(data, _project):

    ###TODO fix the below clean up needed
    print(data)

    if _project.pyplot_flag:

        debug("PyPlot is enabled")
        import matplotlib
        matplotlib.use("Agg", warn=False, force=True)
        import matplotlib.pyplot as plt

        backend = matplotlib.get_backend()
        debug("Using Pyplot backend: %s" %backend)

        G = nx.DiGraph()
        G.add_edges_from(data)
        f = plt.figure()
        f.patch.set_alpha(0.0)
        pos = nx.spring_layout(G)
        node_labels = {node: node for node in G.nodes()}

        font = {'fontname': 'Arial',
                    'color': 'white',
                    'fontweight': 'bold',
                    'fontsize': 14}
        plt.title("Network connection graph")
        nx.draw(G, pos, node_size=10 , node_color='red', edge_color='red',
                font_color='white', labels=node_labels, font_size=8,
                arrows=False, alpha=0.4)
        #pylab.show()
        f.savefig(_project.report_export_location+"netgraph.png", dpi=200)
    else:
        debug("PyPlot is disabled. No graph")


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
    my_project.init_db(DB_NAME)
    my_project.set_volatility_profile(profile)
    my_project.set_image_name(image)

    vol_netscan(my_project)
    show_json(get_result())