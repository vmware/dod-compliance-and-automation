---
title: "Ansible"
weight: 3
description: >
  How to use and install Ansible
---

[Ansible](https://docs.ansible.com/ansible/latest/index.html) is an IT automation tool. It can configure systems, deploy software, and orchestrate more advanced IT tasks such as continuous deployments or zero downtime rolling updates.

Ansible’s main goals are simplicity and ease-of-use. It also has a strong focus on security and reliability, featuring a minimum of moving parts, usage of OpenSSH for transport (with other transports and pull modes as alternatives), and a language that is designed around auditability by humans–even those not familiar with the program.

Ansible concepts talk about "Control nodes" and "Managed nodes". Controls nodes are the machine that runs Ansible and where it is installed. The managed nodes are systems Ansible is managing and do not require Ansible to be installed.

## Prerequisites

* Linux/UNIX only for control nodes.
* Windows is supported for managed nodes only. You can install Ansible on a WSL instance on Windows.
* Python 3.9 or newer for the latest version. More details [here](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#node-requirement-summary).

## Installation
Installation of Ansible varies by platform with detailed instructions available [here](https://docs.ansible.com/ansible/latest/installation_guide/index.html).

## Concepts
### Playbooks
Ansible Playbooks offer a repeatable, re-usable, simple configuration management and multi-machine deployment system, one that is well suited to deploying complex applications. If you need to execute a task with Ansible more than once, write a playbook and put it under source control. Then you can use the playbook to push out new configurations or confirm the configurations of remote systems.

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
`defaults/main.yml` - Default variables for the role/playbook. These variables have the lowest priority of any variables available, and can be easily overridden by any other variable. We use these variables to enable/disable STIG controls individually.  
`handlers/main.yml` - Sometimes you want a task to run only when a change is made on a machine. For example, you may want to restart a service if a task updates the configuration of that service, but not if the configuration is unchanged. Ansible uses handlers to address this use case. Handlers are tasks that only run when notified.  
`meta/main.yml` -  metadata for the role, including role dependencies and optional Galaxy metadata such as platforms supported.  
`tasks/main.yml` - The main list of tasks that the playbook executes.  
`templates` - Templates that the playbook uses.  For example, any complete files we may be replacing instead of editing.  
`vars/main.yml` - Other variables for the role. We place variables for setting values in here. For example, variables for syslog or ntp servers.  
`playbook.yml` - A list of plays that define the order in which Ansible performs operations, from top to bottom, to achieve an overall goal.  
`requirements.yml` - Some playbooks may depend on collections or other roles and are specified here for installation with the `ansible-galaxy` command.  
`vars-example.yml` - We may provide example vars files to use and customize when running a playbook for your environment. This is where we would recommend specifying any variable values instead of editing the playbook files themselves.  

### Roles
Ansible roles can be thought of as playbooks inside of playbooks and meant to be reusable. Our Photon OS playbooks may be a dependency in another playbook and used as a role so that we do not have to maintain multiple copies of the Photon playbook.  

They have the same folder structure as a playbook and will be inside a `roles` folder in the playbook or specified as a dependency in the `playbook.yml`.

Example `playbook.yml` with roles. Note the Photon role is external to this playbooks structure.
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
A format in which Ansible content is distributed that can contain playbooks, roles, modules, and plugins. You can install and use collections through Ansible Galaxy.  

In this project we primarily use collections to install modules which are the code or binaries that Ansible copies to and executes on each managed node (when needed) to accomplish the action defined in each Task. Each module has a particular use, from administering users on a specific type of database to managing VLAN interfaces on a specific type of network device.

In the example below we are using the `ansible.builtin.template` module.
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
# Install a collection directly from ansible galaxy
ansible-galaxy collection install ansible-posix

# Install a collection from a downloaded tar.gz
ansible-galaxy collection install ansible-posix-1.5.4.tar.gz

# Install a role from a downloaded tar.gz of the role
ansible-galaxy role install --roles-path /usr/share/ansible/roles vmware-photon-3.0-stig-ansible-hardening-v1r9.tar.gz
```

### Tags
Tags in Ansible offer a way to only run a specific task or exclude tasks. In the playbooks provided we tag tasks with STIG IDs and sometimes a category such as sshd if there are many tasks that touch ssh.

When running a playbook you can specify `--tags` or `--skip-tags` at the cli followed by a list of tags.

### Inventory
Ansible automates tasks on managed nodes or “hosts” in your infrastructure, using a list or group of lists known as inventory. You can pass host names at the command line, but most Ansible users create inventory files. Your inventory defines the managed nodes you automate, with groups so you can run automation tasks on multiple hosts at the same time. Once your inventory is defined, you use patterns to select the hosts or groups you want Ansible to run against.

The examples we provide in this documentation just pass host names at the command line but if creating inventory files is desired that can be done as well but is outside of the scope here.

For more information on inventory, see [Building Ansible inventories](https://docs.ansible.com/ansible/latest/inventory_guide/index.html).

### Check mode
Check mode runs a playbook and simulates the results. Not all modules support check mode and we do not write our playbooks with check mode in mind.

## Running Ansible Examples and Common Arguments
The examples below are for running Ansible with the vSphere 8 VCSA profile.

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

## References

For the full Ansible documentation, see [Ansible Documentation](https://docs.ansible.com/ansible/latest/index.html).