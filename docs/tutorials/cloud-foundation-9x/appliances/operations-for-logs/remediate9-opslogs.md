# Remediate VCF Operations for Logs 9.0.0.0
Remediating VCF Operations for Logs 9.0.0.0 for STIG Compliance

## Overview
This tutorial covers remediating the Operations for Logs appliance in VCF deployments.  

> **Important** For the best experience, prior to using the STIG automation provided here please ensure you:  

> - Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
> - Have an understanding of Ansible playbooks and concepts.
> - Have a back out plan so the changes can be rolled back if necessary.
> - Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9x/ansible-playbook-overview.md) and understand the structure of the Ansible playbook provided here.

> **Failure to do so can result in unintended behavior in the environment.**   

The example commands below are specific to the product version and the supported STIG content for the version being run.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations for Logs appliance.
* Ansible Inventory, Vault, and any environment specific variables are updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating Operations for Logs
To remediate Operations for Logs an Ansible playbook has been provided that will target Operations for Logs appliances over SSH and configure any non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations for Logs Server details
In the Ansible inventory file and vault ensure the target Operations for Logs server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations for Logs inventory group and update the existing hosts and add additional hosts as needed.
operations_logs:
  hosts:
    ops_logs_1:
      ansible_host: opslogs1.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_logs_1_root_password }}"
    ops_logs_2:
      ansible_host:
      ansible_user: root
      ansible_password: "{{ var_vault_operations_logs_2_root_password }}"
    ops_logs_3:
      ansible_host:
      ansible_user: root
      ansible_password: "{{ var_vault_operations_logs_3_root_password }}"

# Update the credentials for the target Operations for Logs in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations for Logs credential variables and update and save (:wq)
var_vault_operations_logs_1_root_password:
var_vault_operations_logs_2_root_password:
var_vault_operations_logs_3_root_password:
```

### Running the playbook
To remediate all Operations for Logs rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target only the ops_logs_1 inventory host.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_logs_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations for Logs in inventory named ops_logs_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_logs_1 -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single Operations for Logs in inventory named ops_logs_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_logs_1 -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Run all applicable roles on all Operations for Logs in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_logs -v --ask-vault-pass -e @vault_vcf.yml

# Output example
TASK [photon_5 : PHTN-50-000003 - Copy auditd rules template to /etc/audit/rules.d/audit.STIG.rules.] *************************************************************************************************************************
ok: [ops_logs_1] => {"changed": false, "checksum": "cf48c74900d05cfb656c4454a415a902ca44f749", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "mode": "0640", "owner": "root", "path": "/etc/audit/rules.d/audit.STIG.rules", "size": 4653, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock deny in /etc/security/faillock.conf.] ********************************************************************************************************************************
ok: [ops_logs_1] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock fail_interval in /etc/security/faillock.conf.] ***********************************************************************************************************************
ok: [ops_logs_1] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000005 - Configure DoD Banner in /etc/issue.] ********************************************************************************************************************************************************
ok: [ops_logs_1] => {"changed": false, "checksum": "b5b89ddf36286d4e3190e401fb97622878f622ca", "dest": "/etc/issue", "gid": 0, "group": "root", "mode": "0644", "owner": "root", "path": "/etc/issue", "size": 1299, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000005 - Configure Banner in /etc/ssh/sshd_config.] **************************************************************************************************************************************************
ok: [ops_logs_1] => {"backup": "", "changed": false, "msg": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_logs_1                 : ok=207  changed=5    unreachable=0    failed=0    skipped=62   rescued=0    ignored=0
```

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
To audit the Operations for Logs post-remediation rerun the auditing steps [here](./audit9-opslogs.md).
