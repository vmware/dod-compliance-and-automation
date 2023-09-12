---
title: "Audit VMware Aria Automation 8"
weight: 3
description: >
  Auditing VMware Aria Automation 8 for STIG Compliance
---
## Overview
Auditing VMware Aria Automation for STIG compliance involves scanning the application, the Kubernetes and Docker services running on the appliance, and the underlying Photon OS.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to utilize the versions listed here.  

* The [vmware-vra-8x-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/aria/automation/8.x/inspec/vmware-vra-8x-stig-baseline) profile downloaded.
* The [vmware-photon-3.0-stig-inspec-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/3.0/inspec/vmware-photon-3.0-stig-inspec-baseline) profile downloaded.
* [InSpec/Cinc Auditor 5.22.3](/docs/automation-tools/inspec/)
* [SAF CLI 1.2.11](docs/automation-tools/safcli/)
* [STIG Viewer 2.17](https://public.cyber.mil/stigs/srg-stig-tools/)
* A VMware Aria Automation environment. 8.12 was used in these examples.
* An account with access to VMware Aria Automation.

## Auditing VMware Aria Automation
### Update profile inputs
Included in each of the `vmware-vra-8x-stig-baseline` sub-folders (vra, docker, and kubernetes) is an inspec input file named 'inspec.yml'. 
Additionally, at the top level, there is and example yml file that "rolls up" all of the variables into one file, and can be utilized at the command line.

Update each of the input files (`vra/inspec.yml`, `docker\inspec.yml`, `kubernetes\inspec.yml`) with inputs as shown below containing values relevant to your environment. 
Alternatively, update the single top level file, `inputs-example.yml`, with values specific to your environment.

#### VMware Aria Automation - Application
```yaml
syslogHost: "log.test.local"
syslogPort: "514"
syslogProtocol: "tcp"
syslogSslVerify: "true"
syslogUseSsl: "false"
ntpServers: "['time.server.org']"
maxAuthTries: "2"
verbose: True
allowedCipherSuites: ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
```
#### VMware Aria Automation - Kubernetes
```yaml
manifests_path: '/etc/kubernetes/manifests'
pki_path: '/etc/kubernetes/pki'
kubeadm_conf_path: '/etc/systemd/system/kubelet.service.d/10-kubeadm.conf'
kubectl_path: '/usr/local/bin/kubectl'
kubectl_minversion: 'v1.12.9'
kubernetes_conf_files: ["/etc/kubernetes/admin.conf","/etc/kubernetes/scheduler.conf","/etc/kubernetes/controller-manager.conf"]
kubectl_conf_path: '/etc/kubernetes/admin.conf'
kubelet_conf_path: '/var/lib/kubelet/config.yaml'
kubelet_kubeconf_path: ''
k8s_min_supported_version: 'v1.20.13'
```

### Update the SSH config to allow scan
If the VMware Aria Automation appliance has SSH access disabled, the check and fix scans will not be able to run. SSH must be temporarily enabled to complete the scan, then can be disabled again once the audit is complete.  

```bash
# Connect to the console through vCenter
vi /etc/ssh/sshd_config
# Update PermitRootLogin from no to yes and save
systemctl restart sshd
```

### Run the audit
In this example we will be scanning a target VMware Aria Automation appliance, specifying an inputs file, and outputting a report to the CLI and to a JSON file run from a linux machine.  
```bash
# Note this command is being run from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t ssh://root@aria-automation.domain.path --password 'replaceme' --show-progress --input-file inputs-example.yml --reporter cli json:/tmp/reports/Aria_Automation_8x_STIG_Report.json

# Shown below is the last part of the output at the CLI.
  ✔  CNTR-K8-003270: The Kubernetes admin.conf must have file permissions set to 644 or more restrictive.
     ✔  File /etc/kubernetes/admin.conf is expected not to be more permissive than "0644"
     ✔  File /etc/kubernetes/scheduler.conf is expected not to be more permissive than "0644"
     ✔  File /etc/kubernetes/controller-manager.conf is expected not to be more permissive than "0644"
  ✔  CNTR-K8-003330: The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive.
     ✔  File /etc/kubernetes/pki/apiserver-etcd-client.crt is expected not to be more permissive than "0644"
     ✔  File /etc/kubernetes/pki/front-proxy-client.crt is expected not to be more permissive than "0644"
     ✔  File /etc/kubernetes/pki/ca.crt is expected not to be more permissive than "0644"
     ✔  File /etc/kubernetes/pki/front-proxy-ca.crt is expected not to be more permissive than "0644"

Profile Summary: zz successful controls, zz control failures, zz controls skipped
Test Summary: zz successful, zz failures, zz skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i /tmp/reports/Aria_Automation_8x_STIG_Report.json -o /tmp/reports/Aria_Automation_8x_STIG_Report.ckl --hostname aria-automation.domain.path --fqdn aria-automation.domain.path --ip 10.2.3.4 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look similar to the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/vcf_audit5_ckl_screenshot.png)