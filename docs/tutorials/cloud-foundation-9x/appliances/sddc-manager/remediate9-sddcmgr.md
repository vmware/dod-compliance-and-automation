---
title: "Remediate VCF SDDC Manager 9.x"
weight: 2
description: >
  Remediating VCF SDDC Manager 9.x for STIG Compliance
---
## Overview
This tutorial covers remediating the SDDC Manager appliance in VCF deployments.  

{{% alert title="Important" color="warning" %}}
For the best experience, prior to using the STIG automation provided here please ensure you:  
- Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
- Have an understanding of Ansible playbooks and concepts.
- Have a back out plan so that the changes can be rolled back if necessary.
- Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook_overview/) and understand the structure of the Ansible playbook provided here.

**Failure to do so can result in unintended behavior in the environment.**  



The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.


### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* SSH access to the SDDC Manager appliance.
* Ansible Inventory, Vault, and any environment specific variables are updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating SDDC Manager
To remediate SDDC Manager an Ansible playbook has been provided that will target a single SDDC Manager appliance over SSH and configure any non-compliant controls.  

### Update the SSH config to allow scan
By default the SDDC Manager appliance does not allow root SSH and the `vcf` user does not have the required privileges to complete the scan so root SSH must be temporarily enabled to complete the scan. These steps can be reversed once the remediation is complete.  

```bash
# Allow root SSH into SDDC manager
ssh vcf@sddcmanager.rainpole.local
su -
# Update PermitRootLogin from no to yes
sed -i '/PermitRootLogin no/c\PermitRootLogin yes' /etc/ssh/sshd_config
systemctl restart sshd
```

### Update Ansible Inventory and Vault with target SDDC Manager Server details
In the Ansible inventory file and vault ensure the target SDDC Manager server details are correct.
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the SDDC Manager inventory group and update the existing hosts and add additional hosts as needed.
sddcmanager:
  hosts:
    sddcmgr:
      ansible_host: sddcmanager.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_sddcmgr_root_password }}"

# Update the credentials for the target SDDC Manager in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the SDDC Manager credential variables and update and save (:wq)
var_vault_sddcmgr_root_password:
{{< /tab >}}
{{< /tabpane >}}

### Running the playbook
To remediate all SDDC Manager rules, follow the example below:
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target only the sddcmgr inventory host.
ansible-playbook playbook.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single SDDC Manager in inventory named sddcmgr.
ansible-playbook playbook.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single SDDC Manager in inventory named sddcmgr.
ansible-playbook playbook.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Run all applicable roles on all SDDC Managers in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l sddcmanager -v --ask-vault-pass -e @vault_vcf.yml

# Output example
TASK [photon_5 : PHTN-50-000003 - Copy auditd rules template to /etc/audit/rules.d/audit.STIG.rules.] *************************************************************************************************************************
ok: [sddcmgr] => {"changed": false, "checksum": "cf48c74900d05cfb656c4454a415a902ca44f749", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "mode": "0640", "owner": "root", "path": "/etc/audit/rules.d/audit.STIG.rules", "size": 4653, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock deny in /etc/security/faillock.conf.] ********************************************************************************************************************************
ok: [sddcmgr] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock fail_interval in /etc/security/faillock.conf.] ***********************************************************************************************************************
ok: [sddcmgr] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000005 - Configure DoD Banner in /etc/issue.] ********************************************************************************************************************************************************
ok: [sddcmgr] => {"changed": false, "checksum": "b5b89ddf36286d4e3190e401fb97622878f622ca", "dest": "/etc/issue", "gid": 0, "group": "root", "mode": "0644", "owner": "root", "path": "/etc/issue", "size": 1299, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000005 - Configure Banner in /etc/ssh/sshd_config.] **************************************************************************************************************************************************
ok: [sddcmgr] => {"backup": "", "changed": false, "msg": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
sddcmgr                    : ok=204  changed=13   unreachable=0    failed=0    skipped=65   rescued=0    ignored=0
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
To audit the SDDC Manager post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/appliances/sddc-manager/audit9-sddcmgr/).
