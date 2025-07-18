# Remediate VCF Operations HCX 9.0.0.0
Remediating VCF Operations HCX 9.0.0.0 for STIG Compliance

## Overview
This tutorial covers remediating the Operations HCX appliance in VCF deployments.  

> **Important** For the best experience, prior to using the STIG automation provided here please ensure you:  

> - Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
> - Have an understanding of Ansible playbooks and concepts.
> - Have a back out plan so the changes can be rolled back if necessary.
> - Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook_overview/) and understand the structure of the Ansible playbook provided here.

> **Failure to do so can result in unintended behavior in the environment.**  

The example commands below are specific to the product version and the supported STIG content for the version being run.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations HCX appliance.
* Ansible Inventory, Vault, and any environment specific variables are updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating Operations HCX
To remediate Operations HCX an Ansible playbook has been provided that will target a single Operations HCX appliance over SSH and configure any non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations HCX Server details
In the Ansible inventory file and vault ensure the target Operations HCX server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations HCX inventory group and update the existing hosts and add additional hosts as needed.
operations_hcx_mgr:
  hosts:
    ops_hcx_mgr:
      ansible_host: opshcxmgr.rainpole.local
      ansible_user: admin
      ansible_password: "{{ var_vault_operations_hcx_mgr_admin_password }}"
      ansible_become: true
      ansible_become_method: su
      ansible_become_user: root
      ansible_become_password: "{{ var_vault_operations_hcx_mgr_root_password }}"
operations_hcx_conn:
  hosts:
    ops_hcx_conn_1:
      ansible_host: opshcxconn1.rainpole.local
      ansible_user: admin
      ansible_password: "{{ var_vault_operations_hcx_conn_1_admin_password }}"
      ansible_become: true
      ansible_become_method: su
      ansible_become_user: root
      ansible_become_password: "{{ var_vault_operations_hcx_conn_1_root_password }}"
    ops_hcx_conn2:
      ansible_host: opshcxconn2.rainpole.local
      ansible_user: admin
      ansible_password: "{{ var_vault_operations_hcx_conn_2_admin_password }}"
      ansible_become: true
      ansible_become_method: su
      ansible_become_user: root
      ansible_become_password: "{{ var_vault_operations_hcx_conn_2_root_password }}"

# Update the credentials for the target Operations HCX in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations HCX credential variables and update and save (:wq)
var_vault_operations_hcx_mgr_admin_password:
var_vault_operations_hcx_mgr_root_password:
var_vault_operations_hcx_conn_1_admin_password:
var_vault_operations_hcx_conn_1_root_password:
var_vault_operations_hcx_conn_2_admin_password:
var_vault_operations_hcx_conn_2_root_password:
```

### Running the playbook
To remediate all Operations HCX rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target all Operations HCX nodes in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_hcx_mgr,operations_hcx_conn -v --ask-vault-pass -e @vault_vcf.yml

# Target a single Operations HCX appliance (manager in this example) in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations HCX node in inventory named ops_hcx_mgr.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single Operations HCX in inventory named ops_hcx_mgr.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Output example
TASK [photon_5 : PHTN-50-000003 - Copy auditd rules template to /etc/audit/rules.d/audit.STIG.rules.] *************************************************************************************************************************
ok: [ops_hcx_mgr] => {"changed": false, "checksum": "cf48c74900d05cfb656c4454a415a902ca44f749", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "mode": "0640", "owner": "root", "path": "/etc/audit/rules.d/audit.STIG.rules", "size": 4653, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock deny in /etc/security/faillock.conf.] ********************************************************************************************************************************
ok: [ops_hcx_mgr] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000004 - Configure pam_faillock fail_interval in /etc/security/faillock.conf.] ***********************************************************************************************************************
ok: [ops_hcx_mgr] => {"backup": "", "changed": false, "msg": ""}

TASK [photon_5 : PHTN-50-000005 - Configure DoD Banner in /etc/issue.] ********************************************************************************************************************************************************
ok: [ops_hcx_mgr] => {"changed": false, "checksum": "b5b89ddf36286d4e3190e401fb97622878f622ca", "dest": "/etc/issue", "gid": 0, "group": "root", "mode": "0644", "owner": "root", "path": "/etc/issue", "size": 1299, "state": "file", "uid": 0}

TASK [photon_5 : PHTN-50-000005 - Configure Banner in /etc/ssh/sshd_config.] **************************************************************************************************************************************************
ok: [ops_hcx_mgr] => {"backup": "", "changed": false, "msg": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_hcx_mgr                : ok=174  changed=6    unreachable=0    failed=0    skipped=78   rescued=0    ignored=0
ops_hcx_mgr                : ok=214  changed=6    unreachable=0    failed=0    skipped=78   rescued=0    ignored=0
```

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
To audit the Operations HCX post-remediation rerun the auditing steps [here](./audit9-opshcx.md).
