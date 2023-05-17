---
title: "SAF CLI"
weight: 4
description: >
  How to use and install MITRE's SAF CLI
---

The [MITRE Security Automation Framework (SAF) Command Line Interface (CLI)](https://github.com/mitre/saf) brings together applications, techniques, libraries, and tools developed by MITRE and the security community to streamline security automation for systems and DevOps pipelines.

In this context the SAF CLI is used for the following tasks:
* Creating and applying manual attestations to InSpec results.
* Converting InSpec results to a STIG checklist(CKL) format.
* Converting STIG XCCDF files to InSpec profiles to stub out a new profile.

## Prerequisites

* Windows, Linux, and MAC are supported.

## Installation

Download the package for your OS for a release [here](https://github.com/mitre/saf/releases).

For a full list of installation options, see [Installation](https://github.com/mitre/saf#installation-1).

## Usage

### Creating and applying manual attestations
Manual attestation is helpful in scenarios where a control can't be automated for some reason(no API, policy based, etc) but you would still like to include an evaluation of these controls with your automated reports.

The example covered will work with InSpec results but this process can be applied to any report from various supported security tools in the SAF ecosystem.

#### Creating a manual attestation file
An attestation file can be created using SAF CLI or by just manually creating a file.

Using SAF CLI to create a file
```powershell
# Provide your report.json as input and in this example we are using yml as the format but json is also supported
saf attest create -i .\vSphere_ESXi_8.0.1_GA_21495797_ootb_04-12-2023-09-05.json -o .\attestation-example.yml -t yml

# You can search for controls by entering a partial STIG ID
Enter a control ID, search for a control, or enter 'q' to exit: esxi-80-00000
        ESXI-80-000005: The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.
        ESXI-80-000006: The ESXi host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via the Direct Console User Interface (DCUI).
        ESXI-80-000008: The ESXi host must enable lockdown mode.
# For the control you want to attest to you must enter the control ID exactly since this is case sensitive. You will then be prompted to fill out some questions.
Enter a control ID, search for a control, or enter 'q' to exit: ESXI-80-000006
Attestation explanation: The banner is displayed
Frequency (1d/3d/1wk/2wk/1m/3m/6m/1y/1.5y/custom): 1y
Enter status ((p)assed/(f)ailed): passed
Updated By: RL
Enter a control ID, search for a control, or enter 'q' to exit: q
```

This results in a yaml file that looks like the following:
```yaml
- control_id: ESXI-80-000006
  explanation: The banner is displayed
  frequency: 1y
  status: passed
  updated: 2023-05-17T13:32:32.945Z
  updated_by: RL
```

Now that you know the format it may be easier to just add all of the controls needing manual attestation to the attestation file directly.

#### Applying an attestation file to a result file
The next step is to apply the attestation file to our original report to then create a new one that includes our manual attestations.

```powershell
# Provide the original report followed by the attestation file created then for the output provide a name for a new report
saf attest apply -i .\vSphere_ESXi_8.0.1_GA_21495797_ootb_04-12-2023-09-05.json .\attestation-example.yml -o .\My_new_report_with_attestations.json
```

If we examine the new report we will see this on the control we provided an attestation for:
```json
{
  "code_desc": "Manually verified status provided through attestation",
  "status": "passed",
  "message": "Attestation:\nStatus: passed\nExplanation: The banner is displayed\n\nUpdated: 2023-05-17T13:32:32.945Z\nUpdated By: RL\nFrequency: 1y",
  "start_time": "2023-05-17T13:49:06.601Z"
}
```
Now when we convert this to a CKL file this information will be carried forward.

### Converting InSpec results to CKL

```powershell
saf convert hdf2ckl -i .\My_new_report_with_attestations.json -o my_new_ckl.ckl --hostname myesxihost --fqdn myesxihost.local --ip 10.1.2.3 --mac 00:00:00:00:00:00
```

![alt text](/images/safcli_ckl_findings_details.png)
<img src="/images/safcli_ckl_findings_details.png">

### Converting XCCDF to InSpec