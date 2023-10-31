# vmware-aria-operations-configurations

## Purpose

The intent of this repo is to assist with applying STIGs to the VMware Aria Operations appliances with as much automation as possible. While many of the requirements have been automated, there will still be a few things that may need to be handled manually.

### Requirements

* A Linux system with Ansible installed. (Linux subsystem for Windows also works)
* This ansible repo for VMware Aria Operations STIGs. 
* Connectivity to the VMware Aria Operations systems.
* The root credentials for the VMware Aria Operations systems.
* A text editor

### Process

* Snapshot all VMware Aria Operations VMs
* Validate that you took snapshots of all VMware Aria Operations VMs
* Have someone else validate that you took snapshots of all VMware Aria Operations VMs
* Did I mention taking snapshots of all VMware Aria Operations VMs?
* Clone this repo
* Create or edit the inventory.yml file to add your hosts and account information (Alternatively, specify a single host to run against at the command line - see examples below)

To run the playbook with all modules:
`ansible-playbook -i vrops_inventory.yml playbook.yml -k -v -b`

To run the playbook with all the modules and specify the target:
`ansible-playbook -i 'FQDN or IP', -u 'root' playbook.yml -k -v -b`

To run the playbook against just a single module, such as postgres, add '-t {task}' to the command:
`ansible-playbook -i vrops_inventory.yaml vrops_stig.yaml -C -D -t postgres`

You can find the name of the tasks available to run against in %repo-folder%/roles/[role]/tasks/main.yml

* If there are any errors, track them down in the logs and notate them in the configuration workbook for the task and STIG-ID.
You can then comment out the offending task in the [role].yaml file for the task that was run found in the %repo-folder%/roles/[role]/tasks/ directory.
If the system ends up in an unrecoverable state, revert to the snapshots and try again.
If you don't have snapshots, please refer to the first four steps of the process.
