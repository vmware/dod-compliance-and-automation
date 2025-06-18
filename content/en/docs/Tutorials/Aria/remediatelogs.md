---
title: "Remediate VMware Aria Operations for Logs 8"
weight: 6
description: >
  Remediating VMware Aria Operations for Logs 8.x for STIG Compliance
---
## Overview
Remediating VMware Aria Operations for Logs for STIG compliance involves configuring cassandra, tc server, photon, and the appliance.

When remediating we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration affecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

Ansible will be used to perform remediation.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.16.7
* A VMware Aria Operations for Logs 8.14 or newer environment.
* An account with sufficient privileges to configure VMware Aria Suite Lifecycle.

### Assumptions
* Commands are initiated from a Linux machine.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.
* The dependent Photon OS Ansible roles(Photon 4.0) installed and available. Verify role installation with `ansible-galaxy role list`.

## Remediate VMware Aria Operations for Logs (Appliance and/or Product Controls)
{{% alert title="Important" color="primary" %}}
The example commands below are specific to the product version and the supported STIG content for the version being run.
{{% /alert %}}

{{% alert title="Warning" color="warning" %}}
The playbook will attempt to back up configuration files before updating and place them under the /tmp directory in a folder directly on the appliance, but before remediating it is highly advised to have a backup and/or snapshot available if a rollback is required.
{{% /alert %}}

An Ansible playbook has been provided that will target a single VMware Aria Operations for Logs server over SSH and configure any non-compliant controls.  

### Running the playbook
To run all of the controls, follow the example below:
* Navigate to the Ansible playbook folder  
`cd /usr/share/stigs/aria/operations-for-logs/8.x/v1r4-srg/ansible/vmware-vrli-8.x-stig-ansible-hardening`

* The -k parameter will prompt for password.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b`

* Output example:  
```
SSH password:

PLAY [VRLI 8.x Remediation Automation] ******************************************************

TASK [Gathering Facts] **********************************************************************
ok: [10.225.1.3]

TASK [ariaopslogs : Include ariaopslogs] ****************************************************
included: /usr/stigs/vmware-vrli-8.x-stig-ansible-hardening/roles/ariaopslogs/tasks/ariaopslogs.yml for 10.10.10.20

TASK [ariaopslogs : Generate sessionId] *****************************************************
ok: [10.225.1.3] => {"access_control_expose_headers": "X-Content-Type-Options,X-LI-Build", "changed": false, "connection": "close", "content_length": "223", "content_type": "application/json; charset=UTF-8", "cookies": {}, "cookies_string": "", "date": "Tue, 23 Jul 2024 22:19:09 UTC", "elapsed": 0, "json": {"sessionId": "k6USJl6s+PXLuCz4gXgVJJ9WwJu9V9Emi8YwaozwETk8u43TAKAVsXFM4JNipoat7tjai6dj/", "ttl": 1800, "userId": "c17ae391-df17-4954-8a3a-7545e87c"}, "msg": "OK (223 bytes)", "redirected": false, "status": 200, "url": "https://10.10.10.20:9543/api/v2/sessions", "x_content_type_options": "nosniff", "x_li_build": "24021974"}

TASK [ariaopslogs : Extract & save sessionId] ***********************************************
ok: [10.225.1.3] => {"ansible_facts": {"session_id": "k6USJl6s+PXLuCz4gXgVJJ9WwJu9V9Emi8YwaozwETKUKPWnx8F6L+1BQb7hk6Tk8u43TAKAVsXFM4JNipokvWlziI3K8NmaoDw1fsGJat7tjai6dj/"}, "changed": false}

TASK [cassandra : Include cassandra] ********************************************************
included: /usr/stigs/vmware-vrli-8.x-stig-ansible-hardening/roles/cassandra/tasks/cassandra.yml for 10.225.1.3

TASK [cassandra : VLIC-8X-000007 - Check log conf file permissions] *************************
ok: [10.225.1.3] => {"changed": false, "cmd": "stat -c \"%a:%U:%G\" /usr/lib/loginsight/application/lib/apache-cassandra-4.1.4/conf/cassandra.yaml;", "delta": "0:00:00.011136", "end": "2024-07-23 22:19:13.212163", "msg": "", "rc": 0, "start": "2024-07-23 22:19:13.201027", "stderr": "", "stderr_lines": [], "stdout": "644:root:root", "stdout_lines": ["644:root:root"]}

TASK [cassandra : VLIC-8X-000007 - Verify and update conf file permissions] *****************
changed: [10.225.1.3] => (item=644:root:root) => {"ansible_loop_var": "item", "changed": true, "gid": 0, "group": "root", "item": "644:root:root", "mode": "0640", "owner": "root", "path": "/usr/lib/loginsight/application/lib/apache-cassandra-4.1.4/conf/cassandra.yaml", "size": 88384, "state": "file", "uid": 0}

TASK [tcserver : Include tcserver] **********************************************************
included: /usr/stigs/vmware-vrli-8.x-stig-ansible-hardening/roles/tcserver/tasks/tcserver.yml for 10.225.1.3

TASK [tcserver : Backup files - Create time stamp] ******************************************
ok: [10.225.1.3] => {"ansible_facts": {"backup_timestamp": "2024-07-21-19-36-12"}, "changed": false}

....

PLAY RECAP **********************************************************************************
10.10.10.20    : ok=10   changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

* A more conservative and preferred approach is to target any non-compliant controls or run each component separately to allow for functional testing in between.
* Providing the tag "cassandra" will instruct the playbook to only run the cassandra role. This tag can be seen in each role's task/main.yml file.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t cassandra`

* Providing the tag "VLIC-8X-000007" will instruct the playbook to only run the task tagged with the STIG ID of VLIC-8X-000007.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t VLIC-8X-000007`
