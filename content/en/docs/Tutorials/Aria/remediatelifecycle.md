---
title: "Remediate VMware Aria Suite Lifecycle 8"
weight: 4
description: >
  Remediating VMware Aria Suite Lifecycle 8.x for STIG Compliance
---
## Overview
Remediating VMware Aria Suite Lifecycle for STIG compliance involves configuring nginx, postgres, photon, and the appliance.

When remediating we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration effecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

Ansible will be used to perform remediation.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.16.7
* A VMware Aria Suite Lifecycle 8.14 or newer environment.
* An account with sufficient privileges to configure VMware Aria Suite Lifecycle.

### Assumptions
* Commands are initiated from a Linux machine.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy roles install -r requirements.yml`.
* The dependent Photon OS Ansible roles(Photon 3.0) installed and available. Verify role installation with `ansible-galaxy role list`.

## Remediate VMware Aria Suite Lifecycle (Appliance and/or Product Controls)
{{% alert title="Important" color="primary" %}}
The example commands below are specific to the product version and the supported STIG content for the version you are running.
{{% /alert %}}

{{% alert title="Warning" color="warning" %}}
The playbook will attempt to backup configuration files before updating and place them under the /tmp directory in a folder directly on the appliance, but before remediating it is highly advised to have a backup and/or snapshot available if a rollback is required.
{{% /alert %}}

An Ansible playbook has been provided that will target a single VMware Aria Suite Lifecycle server over SSH and configure any non-compliant controls.  

### Running the playbook
To run all of the controls, follow the example below:
* Navigate to the Ansible playbook folder  
`cd /usr/share/stigs/aria/lifecycle/8.x/v1r2-srg/ansible/vmware-vrslcm-8.x-stig-ansible-hardening`

* The -k parameter will prompt for password.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b`

* Output example:  
```
SSH password:

PLAY [VRLCM 8.x Remediation Automation] *********************************************************************************

TASK [Gathering Facts] **************************************************************************************************
ok: [10.225.1.22]

TASK [nginx : Include nginx] ********************************************************************************************
included: /usr/stigs/LCM_ANSIBLE/vmware-vrlcm-8.x-stig-ansible-hardening/roles/nginx/tasks/nginx.yml for 10.225.1.22

TASK [nginx : Backup nginx.conf - Create time stamp] ********************************************************************
ok: [10.225.1.22] => {"ansible_facts": {"backup_timestamp": "2024-07-21-19-49-12"}, "changed": false}

TASK [nginx : Backup nginx.conf - If restoring be sure to restore permissions that original file had!!] *****************
ok: [10.225.1.22] => {"changed": false, "checksum": "a607028d0dca90b99f9288409d0943f", "dest": "/tmp/ansible-backups-vrlcm-nginx-2024-07-21-19-49-12/nginx.conf", "gid": 0, "group": "root", "md5sum": "dc629a0d27436898449629b", "mode": "0750", "owner": "root", "size": 7806, "src": "/etc/nginx/nginx.conf", "state": "file", "uid": 0}

TASK [nginx : VLMN-8X-000019 - Check log file permissions] **************************************************************
ok: [10.225.1.22] => {"changed": false, "cmd": "find /var/log/nginx/* -xdev -type f -a '(' -perm -640 -o -not -user root -o -not -group root ')' -exec ls {} \\;", "delta": "0:00:00.007661", "end": "2024-07-23 22:32:20.151514", "msg": "", "rc": 0, "start": "2024-07-23 22:32:20.143853", "stderr": "", "stderr_lines": [], "stdout": "/var/log/nginx/access.log\n/var/log/nginx/error.log", "stdout_lines": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]}

TASK [nginx : VLMN-8X-000019 - Verify and update file permissions] ******************************************************
changed: [10.225.1.22] => (item=/var/log/nginx/access.log) => {"ansible_loop_var": "item", "changed": true, "gid": 0, "group": "root", "item": "/var/log/nginx/access.log", "mode": "0640", "owner": "root", "path": "/var/log/nginx/access.log", "size": 165, "state": "file", "uid": 0}
changed: [10.225.1.22] => (item=/var/log/nginx/error.log) => {"ansible_loop_var": "item", "changed": true, "gid": 0, "group": "root", "item": "/var/log/nginx/error.log", "mode": "0640", "owner": "root", "path": "/var/log/nginx/error.log", "size": 533, "state": "file", "uid": 0}

....

PLAY RECAP **************************************************************************************************************
10.225.1.22      : ok=9    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

* A more conservative and preferred approach is to target any non-compliant controls or run each component separately to allow for functional testing in between.
* Providing the tag "nginx" will instruct the playbook to only run the nginx role. This tag can be seen in each role's task/main.yml file.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t nginx`

* Providing the tag "VLMN-8X-000019" will instruct the playbook to only run the task tagged with the STIG ID of VLMN-8X-000019.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t VLMN-8X-000019`
