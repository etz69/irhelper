## This a very simple/silly command processor
## It supports various predefined commands
## You call the command pass relevant arguments and it returns exit code and
## an dict with results
## Currently only supports command in serial and sync :/

import modules.cmds as ircmd


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

    def get_cmd_desc(self,cmd_name):
        return "Not implemented"

    def prep_cmd(self, cmd_name, cmd_arguments, GLOBALS):
        if not self._command_support(cmd_name):
            self.result['status'] = False
            self.result['cmd_results'] = "Command not implemented"
            return self.result
        else:
            self._execute_cmd(cmd_name, cmd_arguments, GLOBALS)
            return self.result

    def _execute_cmd(self, cmd_name, cmd_arguments, GLOBALS):
        m = Modules()
        func = getattr(m, cmd_name)
        self.result = func(cmd_arguments, GLOBALS)

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


    def vol_imageinfo(self, cmd_args, GLOBALS):
        '''
        Retrieves basic image info such as the type, profiles, KDGB etc..

        Args:
            cmd_args (str): The file path

            GLOBALS (dict): Global dict variables

        Returns:
            dict: Returns standard module response dict
        '''
        ircmd.vol_imageinfo_module.vol_imageinfo(cmd_args, GLOBALS)
        return ircmd.vol_imageinfo_module.get_result()


    def vol_netscan(self, cmd_args, GLOBALS):
        '''
        Runs different modules to discover network related artifacts

        Args:
            cmd_args (str): The file path

            GLOBALS (dict): Global dict variables

        Returns:
            dict: Returns standard module response dict
        '''

        ircmd.vol_netscan_module.vol_netscan(cmd_args, GLOBALS)
        return ircmd.vol_netscan_module.get_result()

    def vol_pslist(self, cmd_args, GLOBALS):
        '''
        Get as much as possible process information and dump pslist binaries
        to disk. This module will also run ``exiftool``

        Args:
            cmd_args (str): The file path

            GLOBALS (dict): Global dict variables

        Returns:
            dict: Returns standard module response dict
        '''

        ircmd.vol_pslist_module.vol_pslist(cmd_args, GLOBALS)
        return ircmd.vol_pslist_module.get_result()

    def vol_getosversion(self, cmd_args, GLOBALS):
        '''
        Reads registry keys and tries to identify OS version information

        Args:
            cmd_args (str): The file path

            GLOBALS (dict): Global dict variables

        Returns:
            dict: Returns standard module response dict
        '''

        ircmd.vol_getosversion_module.vol_getosversion(cmd_args, GLOBALS)
        return ircmd.vol_getosversion_module.get_result()

    def vol_regdump(self, cmd_args, GLOBALS):
        '''
        Dumps SAM registry and tries to extract user information

        Args:
            cmd_args (str): The file path

            GLOBALS (dict): Global dict variables

        Returns:
            dict: Returns standard module response dict
        '''

        ircmd.vol_regdump_module.vol_regdump(cmd_args, GLOBALS)
        return ircmd.vol_regdump_module.get_result()

