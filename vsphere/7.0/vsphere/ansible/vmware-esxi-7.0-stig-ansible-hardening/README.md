# vmware-esxi-7.0-stig-ansible-hardening
VMware vSphere ESXi 7.0 STIG Readiness Guide Ansible Playbook

Version: Version 1 Release 4: 28 October 2022 

STIG Type: STIG Readiness Guide  

## Tool Requirements
- Tested with Ansible core 2.14.0
- PowerCLI (latest)
- PowerShell Core 7.2

## Role Requirements
- Each role contains a `requirements.yml` (use Ansible Galaxy to install dependencies)


## Playbook Structure
- esxi-stig.yml (the playbook to run both roles).
- /roles/esxi-remediation-local (runs majority of lockdowns via Ansible ESXi Modules + a few PowerCLI calls.)
- /roles/esxi-remediation-remote (runs STIG lockdowns by directly SSH-ing to endpoints.) 

## How to Run
**Note**: Variables need to be configured prior to execution (ex: vcenter_username)

Example of running both roles
```
ansible-playbook -i inventory_file esxi-stig.yml -v --ask-vault -k -K
```

Example of running remote role (if remote user is not root, additionall flag of -K is needed)
```
ansible-playbook -i inventory_file esxi-stig.yml --tag remote -v --ask-vault -k
```

Example of running local role 
```
ansible-playbook -i inventory_file esxi-stig.yml --tag local -v --ask-vault -K
```

Example of running individual lockdowns (in this example both are in esxi-remediation-local) 
```
ansible-playbook -i inventory_file esxi-stig.yml --tag ESXI-70-000002,ESXI-70-000003 -v --ask-vault -K
```

## STIG Control Coverage

csv in-progress
