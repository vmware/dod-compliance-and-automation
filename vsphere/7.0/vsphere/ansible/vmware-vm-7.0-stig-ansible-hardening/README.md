
# vmware-vm-7.0-stig-ansible-hardening
VMware vSphere VM 7.0 STIG Readiness Guide Ansible Playbook

Version: Version 1 Release 4: 28 October 2022 

STIG Type: STIG Readiness Guide  

## Tool Requirements
- Tested with Ansible core 2.14.0
- PowerCLI (latest)
- PowerShell Core 7.2

## Role Requirements
- Role contains a `requirements.yml` (use Ansible Galaxy to install dependencies)


## Playbook Structure
- vm-stig.yml (the playbook to run both roles).
- /roles/esxi-remediation-local (runs majority of lockdowns via Ansible ESXi Modules + a few PowerCLI calls.)
- /roles/esxi-remediation-remote (runs STIG lockdowns by directly SSH-ing to endpoints.) 

## How to Run
**Note**: Variables need to be configured prior to execution (ex: vcenter_username)

Example of running role
```
ansible-playbook -i inventory_file vm-stig.yml -v --ask-vault -K
```

Example of running individual lockdowns
```
ansible-playbook -i inventory_file esxi-stig.yml --tag VMCH-70-000001,VMCH-70-000002 -v --ask-vault -K
```

## STIG Control Coverage

csv in-progress
