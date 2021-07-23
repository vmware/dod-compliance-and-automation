# vmware-vsphere-7.0-stig-ansible-hardening
An ansible playbook to harden VMware vSphere 7.0 against the draft DISA vSphere 7.0 STIG

## Requirements
- VMware vSphere 7.0 DISA STIG Draft
- Tested with Ansible 2.10.11
- Tested with vCenter 7.0 U1d
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10 to run an Unbuntu box for example
- Assumes a vCenter server is used to manage ESXi and Virtual Machines
- Assumes ESXi hosts share common credentials

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the VMware community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.vmware

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.vmware
```

### Required Python libraries

VMware community collection depends upon following third party libraries:

* [`Pyvmomi`](https://github.com/vmware/pyvmomi) >= 6.7.1.2018.12
* [`vSphere Automation SDK for Python`](https://github.com/vmware/vsphere-automation-sdk-python/)
* [`vSAN Management SDK for Python`](https://code.vmware.com/web/sdk/vsan-python)

### Installing required libraries and SDK

Installing collection does not install any required third party Python libraries or SDKs. You need to install the required Python libraries using following command:

    pip install -r ~/.ansible/collections/ansible_collections/community/vmware/requirements.txt

## Status
Complete Components

- ESXi
- vCenter
- Virtual Machines

This playbook does not cover the vCenter Appliance controls which are in a companion Ansible Playbook.

## Playbook Structure
Using the ESXi role as an example...  

- vsphere.yml - Main playbook to run
- inv.esxi.yml - Inventory file for ESXi hosts to remediate
- /roles/esxi/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/esxi/handlers/main.yaml - handlers referenced in the tasks if any
- /roles/esxi/tasks/main.yml - Default role playbook
- /roles/esxi/tasks/esxi.yml - ESXi playbook
- /roles/esxi/templates - Any templates used
- /roles/esxi/vars/main.yml - variables reference by task.  Update these variables as needed for your environment.

## How to run

### Setup playbook for your environment

- Update the inventory files for ESXi or VMs with the targeted systems to remediate
- Update vsphere.yml with vCenter connection information

Run all controls for ESXi hosts in inventory. Prompts for root user password for SSH to ESXi hosts and displays verbose output  
```
ansible-playbook -i inv.esxi.yml vsphere.yml --tags esxi -v -k 
```

Run a specific control for ESXi hosts in inventory. Prompts for root user password for SSH to ESXi hosts and displays verbose output  
```
ansible-playbook -i inv.esxi.yml vsphere.yml -v --tags ESXI-70-000059 -k
```

Run all controls for virtual machines in inventory.  
```
ansible-playbook -i inv.vms.yml vsphere.yml --tags vms -v
```


## STIG Control Coverage

- Enabled means the playbook will run it by default 
- Manual means it is either a policy control or a technical control that must be manually addressed due do its need for human review
- The version columns note that a control is compliant out of the box for that version

| STIG ID        | Enabled?           | Manual?            | Default U1d? |
|----------------|--------------------|--------------------|--------------|
| ESXI-70-000001 | :heavy_check_mark: | :x:                | :x:          |
| ESXI-70-000002 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000003 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000004 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000005 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000006 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000007 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000008 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000009 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000010 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000012 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000013 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000014 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000015 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000016 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000020 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000021 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000022 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000023 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000025 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000026 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000027 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000030 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000031 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000032 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000033 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000034 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000035 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000036 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000037 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000038 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000039 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000041 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000042 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000043 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000045 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000046 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000047 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000048 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000049 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000050 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000053 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000054 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000055 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000056 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000057 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000058 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000059 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000060 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000061 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000062 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000063 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000064 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000065 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000070 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000072 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000074 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000076 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000078 | :x:                | :heavy_check_mark: |              |
| ESXI-70-000079 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000080 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000081 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000082 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000083 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000086 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000088 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000089 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000090 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000092 | :heavy_check_mark: | :x:                |              |
| ESXI-70-000093 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000001 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000003 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000004 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000005 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000007 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000009 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000012 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000013 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000014 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000015 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000016 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000018 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000019 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000020 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000023 | :heavy_check_mark: | :x:                |              |
| VCSA-70-000024 | :heavy_check_mark: | :x:                |              |
| VCSA-70-000031 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000034 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000035 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000036 | :heavy_check_mark: | :x:                |              |
| VCSA-70-000039 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000040 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000041 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000042 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000043 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000045 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000046 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000047 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000052 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000054 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000055 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000057 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000058 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000059 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000060 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000061 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000062 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000063 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000064 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000065 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000066 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000067 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000068 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000069 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000070 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000071 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000072 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000073 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000074 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000075 | :heavy_check_mark: | :x:                |              |
| VCSA-70-000076 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000077 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000078 | :heavy_check_mark: | :x:                |              |
| VCSA-70-000079 | :x:                | :heavy_check_mark: |              |
| VCSA-70-000080 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000001 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000002 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000003 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000004 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000005 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000006 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000007 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000008 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000009 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000010 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000011 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000012 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000013 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000014 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000015 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000016 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000017 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000018 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000019 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000020 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000021 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000022 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000023 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000024 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000025 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000026 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000027 | :heavy_check_mark: | :x:                |              |
| VMCH-70-000028 | :x:                | :heavy_check_mark: |              |
| VMCH-70-000029 | :x:                | :heavy_check_mark: |              |


## License
Copyright 2020-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
