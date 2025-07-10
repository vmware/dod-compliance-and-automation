---
title: "Remediate VCF Operations for Networks 9.x"
weight: 2
description: >
  Remediating VCF Operations for Networks 9.x for STIG Compliance
---
## Overview
This tutorial covers remediating the Operations for Networks appliance in VCF deployments.  

{{% alert title="Important" color="warning" %}}
For the best experience, prior to using the STIG automation provided here please ensure you:  
- Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
- Have an understanding of Ansible playbooks and concepts.
- Have a back out plan so that the changes can be rolled back if necessary.
- Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook_overview/) and understand the structure of the Ansible playbook provided here.
- Understand that if needed the Ubuntu 22.04 Ansible role will initiate a reboot to complete the remediation tasks.  

**Failure to do so can result in unintended behavior in the environment.**  



The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.


### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations for Networks appliance.
* Ansible Inventory, Vault, and any environment specific variables are updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating Operations for Networks
To remediate Operations for Networks an Ansible playbook has been provided that will target Operations for Networks appliances over SSH and configure any non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations for Networks Server details
In the Ansible inventory file and vault ensure the target Operations for Networks server details are correct.
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations for Networks inventory group and update the existing hosts and add additional hosts as needed.
operations_networks_platform:
  hosts:
    ops_networks_platform_1:
      ansible_host: opsnet1.rainpole.local
      ansible_user: support
      ansible_password: "{{ var_vault_operations_networks_platform_1_support_password }}"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root
    ops_networks_platform_2:
      ansible_host:
      ansible_user: support
      ansible_password: "{{ var_vault_operations_networks_platform_2_support_password }}"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root
    ops_networks_platform_3:
      ansible_host:
      ansible_user: support
      ansible_password: "{{ var_vault_operations_networks_platform_3_support_password }}"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root
operations_networks_proxy:
  hosts:
    ops_networks_proxy_1:
      ansible_host: opsnetproxy1.rainpole.local
      ansible_user: support
      ansible_password: "{{ var_vault_operations_networks_proxy_1_support_password }}"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root

# Update the credentials for the target Operations for Networks in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations for Networks credential variables and update and save (:wq)
var_vault_operations_networks_platform_1_support_password:
var_vault_operations_networks_platform_2_support_password:
var_vault_operations_networks_platform_3_support_password:
var_vault_operations_networks_proxy_1_support_password:
{{< /tab >}}
{{< /tabpane >}}

### Running the playbook
To remediate all Operations for Networks rules, follow the example below:

**Note - Only the supported Ubuntu 22.04 STIG rules are enabled via the group inventory vars. Modifications that impact this filtering are not supported.**  
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target all Operations for Networks nodes in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_networks_platform,operations_networks_proxy -v --ask-vault-pass -e @vault_vcf.yml

# Target a single Operations for Networks appliance in inventory and remediate all rules.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations for Networks node in inventory named ops_networks_platform_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml --tags UBTU-22-211015

# Run a specific role by tag on a single Operations for Networks in inventory named ops_networks_platform_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml --tags ubuntu-2204

# Output example
TASK [ops_net_platform_nginx : NGINX - Determine if deployment is a cluster or standalone.] ***********************************************************************************************************************************
ok: [ops_networks_platform_1] => {"changed": false, "stat": {"exists": false}}

TASK [ops_net_platform_nginx : NGINX - Get contents of /home/ubuntu/build-target/deployment/deployment-set.info.] *************************************************************************************************************
skipping: [ops_networks_platform_1] => {"changed": false, "skip_reason": "Conditional result was False"}

TASK [ops_net_platform_nginx : NGINX - Determine how many nodes are in the cluster.] ******************************************************************************************************************************************
skipping: [ops_networks_platform_1] => {"changed": false, "skip_reason": "Conditional result was False"}

TASK [ops_net_platform_nginx : NGINX - Copy configuration template to overwrite /etc/nginx/sites-available/vnera on a standalone deployment.] *********************************************************************************
changed: [ops_networks_platform_1] => {"changed": true, "checksum": "9ade25933a9c8ae7aa8d586ad487bf9082bc6a6d", "dest": "/etc/nginx/sites-available/vnera", "gid": 0, "group": "root", "md5sum": "843302a74f2278fcf5ad33dc20109044", "mode": "0600", "owner": "root", "size": 11222, "src": "/home/support/.ansible/tmp/ansible-tmp-1747082966.79966-80337-21644754656657/source", "state": "file", "uid": 0}

TASK [ops_net_platform_nginx : NGINX - Copy configuration template to overwrite /etc/nginx/sites-available/vnera on a 3 node cluster deployment.] *****************************************************************************
skipping: [ops_networks_platform_1] => {"changed": false, "skip_reason": "Conditional result was False"}

TASK [ops_net_platform_nginx : VCFO-9X-000019 - Find logs with incorrect permissions in /var/log/nginx/.] *********************************************************************************************************************
changed: [ops_networks_platform_1] => {"changed": true, "cmd": "find /var/log/nginx/ -xdev -type f -a \\( -not -perm 640 -o \\( -not -user root -a -not -user www-data \\) -o \\( -not -group root -a -not -group adm \\) \\);", "delta": "0:00:00.011035", "end": "2025-05-12 20:49:29.368137", "msg": "", "rc": 0, "start": "2025-05-12 20:49:29.357102", "stderr": "", "stderr_lines": [], "stdout": "/var/log/nginx/error.log\n/var/log/nginx/access.log.2.gz", "stdout_lines": ["/var/log/nginx/error.log", "/var/log/nginx/access.log.2.gz"]}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_networks_platform_1    : ok=35   changed=18   unreachable=0    failed=0    skipped=196  rescued=0    ignored=0
ops_networks_proxy_1       : ok=23   changed=14   unreachable=0    failed=0    skipped=192  rescued=0    ignored=0
{{< /tab >}}
{{< /tabpane >}}

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

### Restore files from backup
If needed, to troubleshoot any issues files can be restored from the backups the Ansible playbook creates (unless disabled!).  

Backed up files can be found in the associated `/tmp/ansible-backups-*` folder and restored from there to their original location.

## Rerun auditing after remediation
To audit the Operations for Networks post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/appliances/operations-for-networks/audit9-opsnet/).
