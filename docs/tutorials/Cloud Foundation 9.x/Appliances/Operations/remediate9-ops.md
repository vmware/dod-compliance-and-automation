---
title: "Remediate VCF Operations 9.x"
weight: 2
description: >
  Remediating VCF Operations 9.x for STIG Compliance
---
## Overview
This tutorial covers remediating the Operations appliances in VCF deployments.  

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
* SSH access to the Operations appliances.
* Ansible Inventory, Vault, and any environment specific variables are updated.
* Enable FIPS on the Operations cluster prior to running the playbook. See rule VCFA-9X-000352.  

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating Operations
To remediate Operations an Ansible playbook has been provided that will target Operations appliances over SSH and configure any non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations Server details
In the Ansible inventory file and vault ensure the target Operations server details are correct.
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations inventory groups and update the existing hosts and add additional hosts as needed.
operations:
  hosts:
    ops_master:
      ansible_host: ops-master.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_master_root_password }}"
    ops_replica:
      ansible_host: ops-replica.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_replica_root_password }}"
operations_data:
  hosts:
    ops_data_1:
      ansible_host: ops-data.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_data_1_root_password }}"
operations_cloud_proxy:
  hosts:
    ops_cp_1:
      ansible_host: ops-cp.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_cp_1_root_password }}"

# Update the credentials for the target Operations in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations credential variables and update and save (:wq)
var_vault_operations_master_root_password:
var_vault_operations_replica_root_password:
var_vault_operations_data_1_root_password:
var_vault_operations_cp_1_root_password:
{{< /tab >}}
{{< /tabpane >}}

### Running the playbook
To remediate all Operations rules, follow the example below:
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target all Operations nodes in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations,operations_data,operations_cloud_proxy -v --ask-vault-pass -e @vault_vcf.yml

# Target a single Operations appliance (master in this example) in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations node in inventory named ops_master.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single Operations in inventory named ops_master.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Output example
TASK [photon_5 : PHTN-50-000003 - Copy auditd rules template to /etc/audit/rules.d/audit.STIG.rules.] *************************************************************************************************************************
ok: [ops_master] => {"changed": false, "checksum": "cf48c74900d05cfb656c4454a415a902ca44f749", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "mode": "0640", "owner": "root", "path": "/etc/audit/rules.d/audit.STIG.rules", "size": 4653, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock deny in /etc/security/faillock.conf.] ********************************************************************************************************************************
ok: [ops_master] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock fail_interval in /etc/security/faillock.conf.] ***********************************************************************************************************************
ok: [ops_master] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000005 - Configure DoD Banner in /etc/issue.] ********************************************************************************************************************************************************
ok: [ops_master] => {"changed": false, "checksum": "b5b89ddf36286d4e3190e401fb97622878f622ca", "dest": "/etc/issue", "gid": 0, "group": "root", "mode": "0644", "owner": "root", "path": "/etc/issue", "size": 1299, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000005 - Configure Banner in /etc/ssh/sshd_config.] **************************************************************************************************************************************************
ok: [ops_master] => {"backup": "", "changed": false, "msg": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_cp_1                   : ok=164  changed=7    unreachable=0    failed=0    skipped=46   rescued=0    ignored=0
ops_data_1                 : ok=226  changed=11   unreachable=0    failed=0    skipped=70   rescued=0    ignored=0
ops_master                 : ok=258  changed=22   unreachable=0    failed=0    skipped=88   rescued=0    ignored=0
ops_replica                : ok=258  changed=22   unreachable=0    failed=0    skipped=88   rescued=0    ignored=0
{{< /tab >}}
{{< /tabpane >}}

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   | Nodes                                  |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------|
| `PHTN-50-000046`     |The Photon operating system must require authentication upon booting into single-user and maintenance modes.                             | All                                    |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

### Restore files from backup
If needed, to troubleshoot any issues files can be restored from the backups the Ansible playbook creates (unless disabled!).  

Backed up files can be found in the associated `/tmp/ansible-backups-*` folder and restored from there to their original location.

## Rerun auditing after remediation
To audit the Operations appliances post-remediation, rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/appliances/operations/audit9-ops/).
