---
title: "Remediate VCF vCenter Server 9.x"
weight: 2
description: >
  Remediating VCF vCenter Server 9.x for STIG Compliance
---
## Overview
This tutorial covers remediating the vCenter server appliance in VCF deployments.  

{{% alert title="Important" color="warning" %}}
For the best experience, prior to using the STIG automation provided here please ensure you:  
- Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
- Have an understanding of Ansible playbooks and concepts.
- Have a back out plan so that the changes can be rolled back if necessary.
- Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook_overview/) and understand the structure of the Ansible playbook provided here.

**Failure to do so can result in unintended behavior in the environment.**  
{{% /alert %}}

{{% alert title="Important" color="primary" %}}
The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.
{{% /alert %}}

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* SSH access to the vCenter server appliance.
* Ansible Inventory, Vault, and any environment specific variables are updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating vCenter Server
To remediate vCenter an Ansible playbook has been provided that will target a single vCenter server appliance over SSH and configure any non-compliant controls.  

### Update the default shell for root
The default shell for root must be changed to `/bin/bash` before running. The appliance shell causes issues with some controls running.

```bash
# SSH to vCenter
Connected to service

    * List APIs: "help api list"
    * List Plugins: "help pi list"
    * Launch BASH: "shell"

Command> shell.set --enabled true
Command> shell
Shell access is granted to root
root@sc1-10-182-131-166 [ ~ ]# chsh -s /bin/bash root
```

### Update Ansible Inventory and Vault with target vCenter Server details
In the Ansible inventory file and vault ensure the target vCenter server details are correct.
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the vCenter inventory group and update the existing hosts and add additional hosts as needed.
vcenter:
  hosts:
    vcenter_mgmt:
      ansible_host: vcenter.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_mgmt_root_password }}"
    vcenter_wld_1:
      ansible_host: vcenter-wld.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_wld_1_root_password }}"

# Update the credentials for the target vCenter Servers in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the vcenter credential variables and update and save (:wq)
var_vault_vcenter_mgmt_root_password:
var_vault_vcenter_wld_1_root_password:
{{< /tab >}}
{{< /tabpane >}}

### Running the playbook
To remediate all VCSA rules, follow the example below:
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target only the vcenter_mgmt inventory host.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single vCenter in inventory named vcenter_mgmt.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single vCenter in inventory named vcenter_mgmt.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Run all applicable roles on all vCenters in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter -v --ask-vault-pass -e @vault_vcf.yml

# Output example
TASK [photon_5 : PHTN-50-000003 - Copy auditd rules template to /etc/audit/rules.d/audit.STIG.rules.] *************************************************************************************************************************
ok: [vcenter_mgmt] => {"changed": false, "checksum": "cf48c74900d05cfb656c4454a415a902ca44f749", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "mode": "0640", "owner": "root", "path": "/etc/audit/rules.d/audit.STIG.rules", "size": 4653, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock deny in /etc/security/faillock.conf.] ********************************************************************************************************************************
ok: [vcenter_mgmt] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock fail_interval in /etc/security/faillock.conf.] ***********************************************************************************************************************
ok: [vcenter_mgmt] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000005 - Configure DoD Banner in /etc/issue.] ********************************************************************************************************************************************************
ok: [vcenter_mgmt] => {"changed": false, "checksum": "b5b89ddf36286d4e3190e401fb97622878f622ca", "dest": "/etc/issue", "gid": 0, "group": "root", "mode": "0644", "owner": "root", "path": "/etc/issue", "size": 1299, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000005 - Configure Banner in /etc/ssh/sshd_config.] **************************************************************************************************************************************************
ok: [vcenter_mgmt] => {"backup": "", "changed": false, "msg": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
vcenter_mgmt               : ok=246  changed=2    unreachable=0    failed=0    skipped=103  rescued=0    ignored=0
{{< /tab >}}
{{< /tabpane >}}

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `PHTN-50-000046`     |The Photon operating system must require authentication upon booting into single-user and maintenance modes.                             |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

### Restore files from backup
If needed, to troubleshoot any issues files can be restored from the backups the Ansible playbook creates (unless disabled!).  

Backed up files can be found in the associated `/tmp/ansible-backups-*` folder and restored from there to their original location.

## Rerun auditing after remediation
To audit the vCenter server post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/appliances/vcenter-server/audit9-vcsa/).
