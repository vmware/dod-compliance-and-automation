
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
- playbook.yml (the playbook to run both roles).
- /roles/esxi-remediation-local (runs majority of lockdowns via Ansible ESXi Modules + a few PowerCLI calls.)
- /roles/esxi-remediation-remote (runs STIG lockdowns by directly SSH-ing to endpoints.) 

## How to Run
**Note**: Variables need to be configured prior to execution (ex: vcenter_username)

Example of running role
```
ansible-playbook -i inventory_file playbook.yml -v --ask-vault -K
```

Example of running individual lockdowns
```
ansible-playbook -i inventory_file playbook.yml --tag VMCH-70-000001,VMCH-70-000002 -v --ask-vault -K
```

## STIG Control Coverage
- Enabled means the playbook will run it by default 
- Manual means it is either a policy control or a technical control that must be manually addressed due do its need for human review
- Ansible VMware Module means that it leverages the VMware.Community Ansible Collection.
- PowerShell/PowerCLI means it uses shell to call pwsh which in turn calls PowerCLI (this is done only when API/Ansible Modules cannot complete the control)

|STIG ID       |Enabled?          |Manual?           |Ansible VMware Module|PowerShell/PowerCLI|
|--------------|------------------|------------------|---------------------|-------------------|
|VMCH-70-000001|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000002|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000003|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000004|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000005|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000006|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000007|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000008|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000009|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000010|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000011|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000012|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000013|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000015|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000016|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000017|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000018|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000019|:heavy_check_mark:|:heavy_check_mark:|:x:                  |:x:                |
|VMCH-70-000020|:heavy_check_mark:|:heavy_check_mark:|:x:                  |:x:                |
|VMCH-70-000021|:heavy_check_mark:|:heavy_check_mark:|:x:                  |:x:                |
|VMCH-70-000022|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000023|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000024|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000025|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
|VMCH-70-000026|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000027|:heavy_check_mark:|:x:               |:heavy_check_mark:   |:x:                |
|VMCH-70-000028|:heavy_check_mark:|:heavy_check_mark:|:x:                  |:x:                |
|VMCH-70-000029|:heavy_check_mark:|:x:               |:x:                  |:heavy_check_mark: |
