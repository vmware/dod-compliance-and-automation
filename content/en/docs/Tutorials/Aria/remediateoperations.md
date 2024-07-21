---
title: "Remediate Aria Operations 8"
weight: 8
description: >
  Remediating VMware Aria Operations 8.x for STIG Compliance
---
## Overview
Remediating VMware Aria Operations for STIG compliance involves configuring apache, the tc server services, photon, postgres, and the appliance.

When remediating we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration effecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

Ansible will be used to perform remediation.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.16.7
* A VMware Aria Operations 8.14 or newer environment.
* An account with sufficient privileges to configure VMware Aria Suite Lifecycle.

### Assumptions
* Commands are initiated from a Linux machine.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository downloaded and extracted to `/usr/share/stigs`.
* Ansible installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy roles install -r requirements.yml`.
* The dependent Photon OS Ansible roles(Photon 4.0 for 8.14 to 8.16, Photon 5.0 for 8.18) installed and available. Verify role installation with `ansible-galaxy role list`.

## Remediate VMware Aria Operations (Appliance and/or Product Controls)
{{% alert title="Important" color="primary" %}}
The example commands below are specific to the product version and the supported STIG content for the version you are running.
{{% /alert %}}

{{% alert title="Warning" color="warning" %}}
The playbook will attempt to backup configuration files before updating and place them under the /tmp directory in a folder directly on the appliance, but before remediating it is highly advised to have a backup and/or snapshot available if a rollback is required.
{{% /alert %}}

An Ansible playbook has been provided that will target a single VMware Aria Operations server over SSH and configure any non-compliant controls.  

### Running the playbook
To run all of the controls, follow the example below:
* Navigate to the Ansible playbook folder  
`cd /usr/share/stigs/aria/operations/8.x/v1r3-srg/ansible/vmware-aria-operations-8.x-stig-ansible-hardening`

* The -k parameter will prompt for password.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b`

* Output example:  
```
SSH password:

PLAY [vmware-aria-operations-8x-stig-ansible-hardening] ************************************************

TASK [Gathering Facts] *********************************************************************************
ok: [10.10.10.20]

TASK [apache : Include apache] *************************************************************************
included: /usr/stigs/vmware-vrops-8.x-stig-ansible-hardening/roles/apache/tasks/apache.yml for 10.10.10.20

....

TASK [ui : Include ui] *********************************************************************************
included: /usr/stigs/vmware-vrops-8.x-stig-ansible-hardening/roles/ui/tasks/ui.yml for 10.225.0.148

TASK [ui : VRPU-8X-000001 - Add or configure maximum concurrent connections permitted - Executor node] *********
changed: [10.225.0.148] => {"actions": {"namespaces": {}, "state": "present", "xpath": "//Executor[@name=\"tomcatThreadPool\"]"}, "changed": true}

TASK [ui : VRPU-8X-000001 - Add or configure maximum concurrent connections permitted - Connector node] *********
changed: [10.225.0.148] => {"actions": {"namespaces": {}, "state": "present", "xpath": "//Connector[not(@executor)] | //Connector[@executor != \"tomcatThreadPool\"]"}, "changed": true}

....

RUNNING HANDLER [ui : Restart UI] **********************************************************************
changed: [10.225.0.148] => {"changed": true, "name": "vmware-vcops-web.service", "state": "started", 
...
}

PLAY RECAP *********************************************************************************************
10.225.0.148    : ok=12   changed=3    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

* A more conservative and preferred approach is to target any non-compliant controls or run each component separately to allow for functional testing in between.
* Providing the tag "ui" will instruct the playbook to only run the ui role. This tag can be seen in each role's task/main.yml file.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t ui`

* Providing the tag "VRPU-8X-000001" will instruct the playbook to only run the task tagged with the STIG ID of VRPU-8X-000001.  
`ansible-playbook -i 10.10.10.20, -u root playbook.yml -k -v -b -t VRPU-8X-000001`
