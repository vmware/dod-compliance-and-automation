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
- playbook.yml (the playbook to run both roles).
- /roles/esxi-remediation-local (runs majority of lockdowns via Ansible ESXi Modules + a few PowerCLI calls.)
- /roles/esxi-remediation-remote (runs STIG lockdowns by directly SSH-ing to endpoints.) 

## How to Run
**Note**: Variables need to be configured prior to execution (ex: vcenter_username)

Example of running both roles
```
ansible-playbook -i inventory_file playbook.yml -v --ask-vault -k -K
```

Example of running remote role (if remote user is not root, additionall flag of -K is needed)
```
ansible-playbook -i inventory_file playbook.yml --tag remote -v --ask-vault -k
```

Example of running local role 
```
ansible-playbook -i inventory_file playbook.yml --tag local -v --ask-vault -K
```

Example of running individual lockdowns (in this example both are in esxi-remediation-local) 
```
ansible-playbook -i inventory_file playbook.yml --tag ESXI-70-000002,ESXI-70-000003 -v --ask-vault -K
```

## STIG Control Coverage
- Enabled means the playbook will run it by default 
- Manual means it is either a policy control or a technical control that must be manually addressed due do its need for human review
- Ansible VMware Module means that it leverages the VMware.Community Ansible Collection.
- PowerShell/PowerCLI/Shell means it uses shell to call pwsh which in turn calls PowerCLI (this is done only when API/Ansible Modules cannot complete the control) OR in the case of remote lockdowns uses Ansible Shell module to directly run esx cli commands

|STIG ID       |Enabled?          |Manual?           |Ansible VMware Module|PowerShell/PowerCLI/Shell|
|--------------|------------------|------------------|---------------------|-------------------------|
|ESXI_70_000001|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000002|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000003|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000004|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000005|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000006|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000007|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000008|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000009|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000010|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000012|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000013|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000014|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000015|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000016|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000020|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000021|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000022|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000023|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000025|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000026|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000027|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000030|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000031|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000032|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000034|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000035|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000036|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000037|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000038|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000039|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000041|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000042|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000043|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000045|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000046|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000047|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000048|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000049|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000050|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000053|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000054|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000055|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000056|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000057|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000058|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000059|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000060|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000061|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000062|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000063|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000064|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000065|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000070|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000072|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000074|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000076|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000078|:x:               |:heavy_check_mark:|:x:                  |:x:                      |
|ESXI_70_000079|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000081|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000082|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000083|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000084|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000085|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000086|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000087|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000088|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000089|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000090|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000091|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI_70_000092|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000093|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000094|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000095|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark:       |
|ESXI_70_000097|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |
|ESXI-70-000274|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                      |

