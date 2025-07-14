# Ansible
## Overview
[Ansible](https://docs.ansible.com/ansible/latest/index.html) is an IT automation tool. It can configure systems, deploy software, and orchestrate more advanced IT tasks such as continuous deployments or zero downtime rolling updates.

Ansible’s main goals are simplicity and ease-of-use. It also has a strong focus on security and reliability, featuring a minimum of moving parts, usage of OpenSSH for transport (with other transports and pull modes as alternatives), and a language that is designed around auditability by humans – even those not familiar with the program.

Ansible concepts talk about "Control nodes" and "Managed nodes". Control nodes are the machines that runs Ansible and where it is installed. Managed nodes are systems managed by Ansible and do not require Ansible to be installed.

## Prerequisites

* Linux/UNIX only for control nodes.
* Windows is supported for managed nodes only. Ansible can be installed on a WSL instance on Windows.
* Python 3.9 or newer for the latest version. More details [here](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#node-requirement-summary).

## Installation
Installation of Ansible varies by platform with detailed instructions available [here](https://docs.ansible.com/ansible/latest/installation_guide/index.html).

## Concepts
### Playbooks
Ansible Playbooks offer a repeatable, re-usable, simple configuration management and multi-machine deployment system, one that is well-suited to deploying complex applications. If a task needs to be invoked with Ansible more than once, a playbook should be written and placed under source control. Then the playbook can be used repeatedly to push out new configurations or confirm the configurations of remote systems.

Playbook structure example:
```
vmware-photon-4.0-stig-ansible-hardening
├── defaults
│   └── main.yml
├── handlers
│   └── main.yml
|── meta
│   └── main.yml
├── tasks
│   ├── main.yml
│   └── photon.yml
├── templates
│   ├── audit.STIG.rules
│   └── issue
├── vars
│   └── main.yml
└── playbook.yml
└── requirements.yml
└── vars-example.yml
```

By default Ansible will look in each directory for a `main.yml` file.  

The purpose of each folder is as follows:  
`defaults/main.yml` - Default variables for the role/playbook. These variables have the lowest priority of any variables available, and can be easily overridden at another level. For VMware STIG controls, these variables are used to enable/disable individual STIG controls.  
`handlers/main.yml` - Sometimes a task should only run when a change is made on a machine. For example, a service may need to be restarted if a task updates the configuration of that service, but not if the configuration is unchanged. Ansible uses handlers to address this use case. Handlers are tasks that only run when notified.  
`meta/main.yml` -  Metadata for the role, including role dependencies and optional Galaxy metadata such as supported platforms.  
`tasks/main.yml` - The main list of tasks that the playbook runs.  
`templates` - Templates that the playbook uses.  For example, any complete files that may be replaced instead of edited.  
`vars/main.yml` - Other variables for the role. Variables for setting values specific to the environment are placed in here. Examples include variables for syslog or ntp servers.  
`playbook.yml` - A list of plays that define the order in which Ansible performs operations, from top to bottom, to achieve an overall goal.  
`requirements.yml` - Some playbooks may depend on collections or other roles and are specified here for installation with the `ansible-galaxy` command.  
`vars-example.yml` - Example vars files may be provided for use and customization when running a playbook for a given environment. It is recommended to specify any variable values here instead of editing the playbook files themselves.  

### Roles
Ansible roles can be thought of as playbooks inside of playbooks, and are meant to be reusable. For example, the Photon OS playbook may be included as a dependency in another playbook and used as a role so that multiple copies of the Photon playbook do not have to be maintained.  

Roles have the same folder structure as a playbook, and will either be included inside a `roles` folder in the playbook, or specified as a dependency in the `playbook.yml`.

Example `playbook.yml` with roles (Note the Photon role is external to this playbook's structure):
```
- name: vmware-vcsa-8.0-stig-ansible-hardening
  hosts: all
  roles:
    - role: vmware-photon-3.0-stig-ansible-hardening
      vars:
        var_syslog_authpriv_log: '/var/log/audit/sshinfo.log'
    - role: eam
    - role: envoy
    - role: lookup
    - role: perfcharts
    - role: postgresql
    - role: sts
    - role: ui
    - role: vami
```

### Collections/Modules
Collections are a format in which Ansible content is distributed that can contain playbooks, roles, modules, and plugins. Collections can be installed and used through Ansible Galaxy.  

Collections are primarily used in this project to install modules, which are the code or binaries that Ansible copies to and runs on each managed node (when needed) to accomplish the action defined in each Task. Each module has a particular use, including from administering users on a specific type of database to managing VLAN interfaces on a specific type of network device.

In the example below the `ansible.builtin.template` module is being used:
```yml
###################################################################################################################################
- name: PHTN-40-000003 - Update audit.STIG.rules file
  tags: [PHTN-40-000003, PHTN-40-000019, PHTN-40-000031, PHTN-40-000076, PHTN-40-000078, PHTN-40-000107, PHTN-40-000173, PHTN-40-000175, PHTN-40-000204, PHTN-40-000238, auditd]
  when: run_auditd_rules | bool
  block:
    - name: PHTN-40-000003 - Copy auditd rules template
      ansible.builtin.template:
        src: audit.STIG.rules
        dest: '{{ var_auditd_rule_file }}'
        owner: root
        group: root
        mode: '0640'
        force: true
      notify:
        - reload auditd
```

For a list of all available modules, see [Index of all Modules](https://docs.ansible.com/ansible/latest/collections/index_module.html).

#### Installing Collections and Roles
```bash
# Install a collection directly from Ansible galaxy
ansible-galaxy collection install ansible-posix

# Install a collection from a downloaded tar.gz
ansible-galaxy collection install ansible-posix-1.5.4.tar.gz

# Install a role from a downloaded tar.gz of the role
ansible-galaxy role install --roles-path /usr/share/ansible/roles vmware-photon-3.0-stig-ansible-hardening-v1r9.tar.gz
```

### Tags
Tags in Ansible offer a way to run only a specific task or to exclude tasks. In the playbooks provided tasks are tagged with STIG IDs, and sometimes also tagged with a category (such as 'sshd') if there are many tasks that comprise that category.

When running a playbook `--tags` or `--skip-tags` can be specified at the cli followed by a list of tags.

### Inventory
Ansible automates tasks on managed nodes or “hosts” in your infrastructure using a list or group of lists known as inventory. Host names can be passed at the command line, but most Ansible users create inventory files. The inventory files define the managed nodes to be automated, including optional groupings so the automation tasks can be run on multiple hosts at the same time. Once the inventory is defined, patterns can be used to select the hosts or groups that the Ansible tasks should run against.

Most of the examples provided in this documentation just pass host names at the command line, but if creating inventory files is desired that can be achieved as well, but is outside of the scope here.

For more information on inventory, see [Building Ansible inventories](https://docs.ansible.com/ansible/latest/inventory_guide/index.html).

### Check mode
Check mode runs a playbook and simulates the results. Not all modules support check mode and the playbooks included here were not written with check mode in mind.

## Running Ansible Examples and Common Arguments
The examples below are for running Ansible with the vSphere 8 VCSA profile (note the comma after the host information):

```bash
# Run all controls on a target vCenter. Prompts for user password(-k), displays verbose output(-v).
ansible-playbook -i '10.1.1.1', -u 'root' /path/to/vmware-vcsa-8.0-stig-ansible-hardening/playbook.yml -k -v

# Specify a vars files to pass variables to the playbook.
ansible-playbook -i '10.1.1.1', -u 'root' /path/to/vmware-vcsa-8.0-stig-ansible-hardening/playbook.yml -k -v --extra-vars @/path/to/vmware-vcsa-8.0-stig-ansible-hardening/vars-example.yml

# Specify a tag to only run tasks that match the tag.
ansible-playbook -i '10.1.1.1', -u 'root' /path/to/vmware-vcsa-8.0-stig-ansible-hardening/playbook.yml -k -v --tags VCEM-80-000001

# Specify a tag to skip tasks that match the tag.
ansible-playbook -i '10.1.1.1', -u 'root' /path/to/vmware-vcsa-8.0-stig-ansible-hardening/playbook.yml -k -v --skip-tags VCEM-80-000001
```

The arguments provided in the example can be combined as needed.

For more options, see [ansible-playbook](https://docs.ansible.com/ansible/latest/cli/ansible-playbook.html).

### Host Key Checking
Ansible enables host key checking by default. Checking host keys guards against server spoofing and man-in-the-middle attacks. If a host is not trusted before running Ansible an error may be shown stating that the authenticity of the host cannot be verified.

This can be corrected by running the following:
```bash
ssh-keyscan -H <IP or FQDN> >> /root/.ssh/known_hosts
```

See [managing-host-key-checking](https://docs.ansible.com/ansible/latest/inventory_guide/connection_details.html#managing-host-key-checking) for more details.

## References

For the full Ansible documentation, see [Ansible Documentation](https://docs.ansible.com/ansible/latest/index.html).