## This a very simple/silly command processor
## It supports various predefined commands
## You call the command pass relevant arguments and it returns exit code and
## an dict with results
## Currently only supports command in serial and sync :/

import modules.cmds as ircmd
from modules.utils.helper import *


class CommandProcessor():

    def __init__(self):
        self.return_code = 0
        self.result = {'status': True, 'message': '', 'cmd_results': ''}
        self.command = ""

    def _command_support(self, cmd_name):
        supported_commands = self.get_commands()
        if cmd_name in supported_commands:
            return True
        else:
            self.result['message'] = "Command not implemented"
            return False

    def get_commands(self):
        m = Modules()
        supported_commands = [func for func in dir(m) if callable(getattr(m, func))]
        return supported_commands

    def get_cmd_desc(self, cmd_name):
        return "Not implemented"

    def prep_cmd(self, **kwargs):
        '''
        Prepares for running the required command from module/cmds

        Args:
            cmd_name: The name of the command to run
            Other: Additional arguments for the module if required

        Returns:
            dict: Returns standard module response dict
        '''

        if kwargs is not None:
            if 'cmd_name' in kwargs:
                self.command = kwargs['cmd_name']
            else:
                self.result['status'] = False
                self.result['cmd_results'] = "Command name is missing"
                return self.result
        else:
            self.result['status'] = False
            self.result['cmd_results'] = "Not enough arguments?"
            return self.result

        if not self._command_support(self.command):
            self.result['status'] = False
            self.result['cmd_results'] = "Command not implemented"
            return self.result
        else:
            self._execute_cmd(**kwargs)
            return self.result

    def _execute_cmd(self,**kwargs):

        m = Modules()
        func = getattr(m, self.command)
        self.result = func(**kwargs)

    def get_result(self):
        return self.result


class Modules():
    """Simple command processor for adding new modules and retrieving results
    All modules return a dict which is of the following format:

    ``result = {'status': True, 'message': '', 'cmd_results': ''}``

    ``status``: If the module completely fails set this to False

    ``message``: A descriptive message , usually to show why it failed

    ``cmd_results``: This is usually a dict containing all the data which will be put in the report template


    """


    def vol_imageinfo(self, **kwargs):
        '''
        Retrieves basic image info such as the type, profiles, KDGB etc..

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_imageinfo_module.vol_imageinfo(_project)
            return ircmd.vol_imageinfo_module.get_result()
        else:
            raise ValueError("Project info is missing")



    def vol_netscan(self, **kwargs):
        '''
        Runs different modules to discover network related artifacts

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_netscan_module.vol_netscan(_project)
            return ircmd.vol_netscan_module.get_result()
        else:
            raise ValueError("Project info is missing")


    def vol_pslist(self, **kwargs):
        '''
        Get as much as possible process information and dump pslist binaries
        to disk. This module will also run ``exiftool``

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_pslist_module.vol_pslist(_project)
            return ircmd.vol_pslist_module.get_result()
        else:
            raise ValueError("Project info is missing")

    def vol_getosversion(self, **kwargs):
        '''
        Reads registry keys and tries to identify OS version information

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_getosversion_module.vol_getosversion(_project)
            return ircmd.vol_getosversion_module.get_result()
        else:
            raise ValueError("Project info is missing")

    def vol_regdump(self, **kwargs):
        '''
        Dumps SAM registry and tries to extract user information

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_regdump_module.vol_regdump(_project)
            return ircmd.vol_regdump_module.get_result()
        else:
            raise ValueError("Project info is missing")


    def vol_malfind_extend(self, **kwargs):
        '''
        Run malfind and analyses the output. ToDo ML for asm

        Args:
            project (project): the project

        Returns:
            dict: Returns standard module response dict
        '''

        if 'project' in kwargs:
            _project = kwargs['project']
            ircmd.vol_malfind_extended_module.vol_malfind_extended(_project)
            return ircmd.vol_malfind_extended_module.get_result()
        else:
            raise ValueError("Project info is missing")

