# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from ansible.errors import AnsibleError
from ansible.plugins.connection import ConnectionBase
from ansible.module_utils._text import to_bytes
from ansible.utils.vars import combine_vars
from pyVim import connect
from pyVmomi import vim, vmodl
import requests,ssl,time

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

class Connection(ConnectionBase):

    transport = 'pyVmomi'

    def __init__(self,  *args, **kwargs):
            
        self.has_pipelining = False
        self.si = None
        self.vm_obj = None

        requests.packages.urllib3.disable_warnings()
        super(Connection, self).__init__(*args, **kwargs)

    def set_host_overrides(self, host, hostvars=None):
        self._vim_host = hostvars.get('ansible_vim_host')
        self._vim_port = int(hostvars.get('ansible_vim_host_port') or 443)
        self._vim_host_user = hostvars.get('ansible_vim_host_user')
        self._vim_host_pass = hostvars.get('ansible_vim_host_pass')
        self._vim_vm_uuid = hostvars.get('ansible_vim_uuid')
        self._vim_vm_user = self._play_context.remote_user
        self._vim_vm_pass = self._play_context.password

    def _vim_connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_NONE
        display.vvv("ESTABLISH VIM CONNECTION FOR USER: %s on PORT %s TO %s" %
            (self._vim_host_user, self._vim_port, self._vim_host), host=self._vim_host)
        try:
            service_instance = connect.SmartConnect(host=self._vim_host,user=self._vim_host_user,pwd=self._vim_host_pass,port=self._vim_port,sslContext=context)
        except vim.fault.InvalidLogin:
            raise AnsibleError("Login failed for user %s" % self._vim_host_user)

        return service_instance

    def _vim_get_toolsstatus(self, vm_obj, running_status=False):
        return vm_obj.guest.toolsRunningStatus
    
    def _vim_get_vm(self):
        content = self.si.RetrieveContent()
        vm_obj = content.searchIndex.FindByUuid(None,self._vim_vm_uuid,True,True)
        if not vm_obj:
            raise AnsibleError("Failed to find vm %s" % self._vim_vm_uuid)
        else:
            tools_status = vm_obj.guest.toolsStatus
            if tools_status == 'toolsNotInstalled':
                raise AnsibleError("VMwareTools not installed")
            elif vm_obj.runtime.powerState != 'poweredOn':
                raise AnsibleError("Vm is not powered on")
            else:
                while (self._vim_get_toolsstatus(vm_obj) == 'guestToolsNotRunning'):
                    time.sleep(1)
                return vm_obj

    def _vim_get_returncode(self,pm,vm,creds,pid):
        while True:
            if pm.ListProcessesInGuest(vm,creds,[pid])[0].exitCode != None:
                returncode = pm.ListProcessesInGuest(vm,creds,[pid])[0].exitCode
                break
        return returncode

    def _vim_get_file(self,content,vm,creds,file):
        try:
            url = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(vm,creds,file)
        except vim.fault.InvalidGuestLogin:
            raise AnsibleError("Guest login failed for user %s" % self._vim_vm_user)
        resp = requests.get(url.url,verify=False,stream=True)
        if resp.status_code == requests.codes.ok:
            return resp
        else:
            raise AnsibleError("File transfer failed with status code %s" % resp.status_code)

    def _vim_put_file(self,content,vm,creds,vm_path,file):
        file_attribute = vim.vm.guest.FileManager.FileAttributes()
        try:
            url = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(vm,creds,vm_path,file_attribute,len(file),True)
        except vim.fault.InvalidGuestLogin:
            raise AnsibleError("Guest login failed for user %s" % self._vim_vm_user)
        resp = requests.put(url,data=file,verify=False)
        if resp.status_code == requests.codes.ok:
            return resp
        else:
            raise AnsibleError("File transfer failed with status code %s" % resp.status_code)

    def _connect(self):
        if not self.si:
            self.si = self._vim_connect()
            self._connected = True
        if not self.vm_obj:
            self.vm_obj = self._vim_get_vm()
        return self
            
    def exec_command(self,cmd,in_data=None,sudoable=True):
        super(Connection, self).exec_command(cmd,in_data=in_data,sudoable=sudoable)
        content = self.si.RetrieveContent()
        if self.vm_obj:
            programPath = '/bin/sh'
            cmd_split = cmd.split('/bin/sh -c ',1)[1]
            cmd = cmd_split
            args = '-c {0} 2> {1} 1> {2}'.format(to_bytes(cmd),'/tmp/ansible_stderr','/tmp/ansible_stdout')

            creds = vim.vm.guest.NamePasswordAuthentication(username=self._play_context.remote_user,password=self._play_context.password)
            pm = content.guestOperationsManager.processManager
            ps = vim.vm.guest.ProcessManager.ProgramSpec(programPath=programPath,arguments=args)
            self._display.vvv("EXEC %s %s" % (programPath,args), host=self.vm_obj.name)
            try:
                pid = pm.StartProgramInGuest(self.vm_obj, creds, ps)
            except vim.fault.InvalidGuestLogin:
                raise AnsibleError("Guest login failed for user %s" % self._vim_vm_user)

            returncode = self._vim_get_returncode(pm,self.vm_obj,creds,pid)
            stdout = self._vim_get_file(content,self.vm_obj,creds,'/tmp/ansible_stdout').content
            stderr = self._vim_get_file(content,self.vm_obj,creds,'/tmp/ansible_stderr').content

            return (returncode,to_bytes(stdout),to_bytes(stderr))

    def put_file(self,in_path,out_path):
        super(Connection, self).put_file(in_path,out_path)
        content = self.si.RetrieveContent()
        creds = vim.vm.guest.NamePasswordAuthentication(username=self._play_context.remote_user,password=self._play_context.password)
        display.vvv('PUT "%s" TO "%s"' % (in_path, out_path),host=self.vm_obj.name)
        try:
            with open(to_bytes(in_path,errors='strict'),'rb') as in_file:
                in_file = in_file.read()
                resp = self._vim_put_file(content,self.vm_obj,creds,out_path,in_file)
        except IOError:
            raise AnsibleFileNotFound('File or module does not exist at: %s' % in_path)

    def fetch_file(self,in_path,out_path):
        content = self.si.RetrieveContent()
        creds = vim.vm.guest.NamePasswordAuthentication(username=self._play_context.remote_user,password=self._play_context.password)
        display.vvv('FETCH "%s" TO "%s"' % (in_path, out_path),host=self.vm_obj.name)
        resp = self._vim_get_file(content,self.vm_obj,creds,in_path)
        try:
            with open(to_bytes(out_path,errors='strict'),'wb+') as out_file:
                for chunk in resp:
                    out_file.write(chunk)
        except IOError:
            raise AnsibleFileNotFound('File or module does not exist at: %s' % in_path)

    def close(self):
        super(Connection, self).close()
        if self.si:
            connect.Disconnect(self.si)
        self._connected = False
