# ansible-vmware

Ansible connection plugin for VMware vSphere.

## Description

This plugins allows running Ansible plays on virtual machines running in VMware Vsphere.

The plugin uses vSphere API guest operations to run the plays on virtual machine guest operating system. This means that Ansible server only has to have connectivity to vSphere host or vCenter and not the individual virtual machines.

VMware tools is required to be running on the guest operating system.

vmware_linux.py must be used with Linux/Unix guests and vmware_windows.py with Windows.

## Dependencies

- Ansible >= 2.0
- pyVmomi
- requests

## Installation

	pip install pyvmomi,requests

## Configuration

Define path to connection plugins directory in `ansible.cfg`:

	[defaults]
	connection_plugins = /path/to/connection_plugins

Copy the vmware_*.py files to connection_plugins directory.

Configure varibles for virtual machines:

	ansible_connection: vmware_linux
	ansible_vim_host: vsphere.example.com
	ansible_vim_host_port: 443
	ansible_vim_host_user: ansible@vsphere.local
	ansible_vim_host_pass: secret
	ansible_user: provisioning
	ansible_password: secret

`ansible_connection`: connection plugin to use.

`ansible_vim_host`: vSphere service to connect to.

`ansible_vim_host_port`: port to connect on.

`ansible_vim_host_user`: username in vSphere. The user has to have Virtual Machine Guest Operations privileges.

`ansible_vim_host_pass`: password of the vSphere user.

`ansible_user`: username in the guest os.

`ansible_password`: password of the user.

It is recommended to use Ansible Vault to encrypt the variables file to protect vSphere credentials.

The plugin identifies virtual machines by their vSphere instanceUuid, which must be specified as ansible_vim_uuid variable for each vm:

	vm1 ansible_vim_uuid=50128c2e-90b7-0e1b-0b36-ea69a654de56
