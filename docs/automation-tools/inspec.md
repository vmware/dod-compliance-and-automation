# Chef InSpec/CINC

## Overview

[Chef InSpec](https://docs.chef.io/inspec/) is an open-source framework for testing and auditing applications and infrastructure. Chef InSpec works by comparing the actual state of your system with the desired state expressed in easy-to-read and easy-to-write Chef InSpec code. Chef InSpec detects violations and displays findings in the form of a report, but puts you in control of remediation.

[Cinc](https://cinc.sh/) is a recursive acronym for CINC Is Not Chef. Chef InSpec is free for non-commercial use so the Cinc project was able to remove any trademarks while still complying with Chef's policies and offer a free for any use alternative. Cinc Auditor is built off of the same code base as Chef InSpec.

## Why InSpec?

Chef InSpec/CINC Auditor is currently utilized to assess products as it is geared specifically towards compliance auditing and reporting. It is also something DoD customers can use, along with the supporting tools from the MITRE Security Automation Framework, to create artifacts needed to accredit their environments for use.

Using a separate tool for auditing than what is used to fix or remediate controls is good practice and provides additional assurances that the configuration is in an agreed upon state from multiple points of view. One can think of this similarly to home builder and inspector roles, where the builder is not relied on to perform inspections and report compliance to building codes.

## Prerequisites

* Windows, Linux, and MAC are supported.

## Installation

### Online

Windows:
```powershell
# Run the following command from a PowerShell prompt
. { iwr -useb https://omnitruck.chef.io/install.ps1 } | iex; install -project inspec
```

Linux:
```bash
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec
```

### Offline
Download the package for your OS [here](https://www.chef.io/downloads/tools/inspec).

## Concepts
### Profiles
In InSpec terms "profiles" are offered to audit products. Simple profiles have the following structure:
```
examples/profile
├── README.md
├── controls
│   ├── example.rb
│   └── control_etc.rb
├── libraries
│   └── extension.rb
|── files
│   └── extras.conf
└── inspec.yml
```

The `inspec.yml` file includes some metadata about the profile and any inputs(variables) and dependencies.

Inputs provide a way to supply values to tests without having to update individual tests with specific values. For example, there may be an input for a syslog server to check that the correct syslog server for the environment is configured. Inputs can be given as an argument at the cli or in an inputs file that is then provided at the cli as well. It is recommended to use an inputs file because it is easier to manage and provide at the cli.

### Dependent Profiles
In many cases profiles can be made up of multiple profiles that are included in the same folder structure but can also be pulled in from other locations.

Dependent profiles are used when a product may have multiple STIGs that need to be audited together, but can also be separated into its own profile for organizational purposes. Another reason to do this is it makes profile reuse easier, such as with Photon OS, which many of our product appliances are based on. Instead of maintaining a profile for Photon within each product, Photon can be maintained separately and it can be called as a dependency into a product's profile. Photon inputs could then be provided and tweaked as necessary for that specific product.

An example of this can be observed in the [vSphere 7 VCSA profile](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/v1r4-stig/vcsa/inspec/vmware-vcsa-7.0-stig-baseline).

An abbreviated structure for this profile:
```
vmware-vcsa-7.0-stig-baseline
├── README.md
├── controls
│   ├── eam.rb
│   └── photon.rb
├── eam
  ├── README.md
  ├── controls
  │   ├── VCEM-70-000001.rb
  │   └── VCEM-70-000002.rb
  ├── libraries    
  │   └── extension.rb
  |── files
  │   └── extras.conf
  └── inspec.yml
├── photon
  ├── README.md
  ├── controls
  │   ├── PHTN-30-000001.rb
  │   └── PHTN-30-000002.rb
  ├── libraries    
  │   └── extension.rb
  |── files
  │   └── extras.conf
  └── inspec.yml
└── inspec.yml
```

For more information on dependent profiles, see [Profile Dependencies](https://docs.chef.io/inspec/profiles/#profile-dependencies).

#### InSpec Vendoring
Dependent profiles are "vendored" or cached into the /vendor folder in the profile. This is important to pay attention to because if changes are made to dependent profiles and this cache is not updated the changes will not be seen when the parent profile is run.

Update the vendor/cache:
```bash
inspec vendor --overwrite
Dependencies for profile /vmware-vcsa-7.0-stig-baseline successfully vendored to /vmware-vcsa-7.0-stig-baseline/vendor
```

### Controls
In each profile, the controls folder contains a file for each STIG control that includes that control's metadata and a test for auditing.

Example control file:
```ruby
control 'ESXI-70-000001' do
  title 'Access to the ESXi host must be limited by enabling lockdown mode.'
  desc  "
    Enabling lockdown mode disables direct access to an ESXi host, requiring the host to be managed remotely from vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging on to a host directly.

    By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESXi, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Security Profile.

    Scroll down to \"Lockdown Mode\" and verify it is set to \"Enabled\" (Normal or Strict).

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Select Name,@{N=\"Lockdown\";E={$_.Extensiondata.Config.LockdownMode}}

    If \"Lockdown Mode\" is disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Security Profile >> Lockdown Mode.

    Click \"Edit...\". Select the \"Normal\" or \"Strict\" radio buttons.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $level = \"lockdownNormal\" OR \"lockdownStrict\"
    $vmhost = Get-VMHost -Name <hostname> | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.ChangeLockdownMode($level)

    Note: In strict lockdown mode, the Direct Console User Interface (DCUI) service is stopped. If the connection to vCenter Server is lost and the vSphere Client is no longer available, the ESXi host becomes inaccessible.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag satisfies: ['SRG-OS-000123-VMM-000620']
  tag gid: 'V-256375'
  tag rid: 'SV-256375r885906_rule'
  tag stig_id: 'ESXI-70-000001'
  tag cci: ['CCI-000054', 'CCI-001682']
  tag nist: ['AC-10', 'AC-2 (2)']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    list = ['lockdownNormal', 'lockdownStrict']
    vmhosts.each do |vmhost|
      command = "(Get-VMHost -Name #{vmhost}).Extensiondata.Config.LockdownMode"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
```

### Train (Transport Interfaces)
Train Plugins allow InSpec to connect to various types of endpoints for auditing. Some common plugins are:
* Local execution
* SSH
* WinRM
* Docker and Podman
* Mock (for testing and debugging)
* AWS as an API
* Azure as an API
* VMware via PowerCLI

For example, a vCenter Appliance is audited using the SSH plugin so a connection is made to vCenter over SSH to perform the audit.

### Reporters
InSpec can provide results in a variety of formats, such as:
* cli
* json
* yaml
* html,html2
* junit

These are useful for system admins to collect and monitor configuration drift as well as for accreditation tasks, such as using the SAF CLI tool to convert results into a CKL file for importing into STIG Viewer.

For more information on reports, see [Reporters](https://docs.chef.io/inspec/reporters/).

### Waivers
Waivers allow documentation as code for the controls that have a waiver/poam in the environment. This is done through a waivers file and can be provided as an argument at the command line.

Example `waivers.yml` file:
```yaml
PHTN-30-000053:
  expiration_date: 2024-12-31
  run: false
  justification: "vRA gets it's IP after sshd starts and causes sshd to fail if this is configured to something other than 0.0.0.0:22"
PHTN-30-000106:
  expiration_date: 2024-12-31
  run: false
  justification: "vRA runs Kubernetes which needs this kernel option to forward traffic"
```

For more information on reports, see [Waivers](https://docs.chef.io/inspec/waivers/).

## Running InSpec Examples and Common Arguments
The examples below are for running InSpec from a Windows based machine with the vSphere 7 VCSA profile.

```powershell
# Run against a target vCenter appliance and output results to CLI
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password'

# Run against a target vCenter appliance, show progress, and output results to CLI and JSON
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json

# Run against a target vCenter appliance and provide an inputs file
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password' --input-file .\inputs-example.yml

# Run against a target vCenter appliance and provide a waivers file
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password' --waiver-file .\waiver-example.yml

# Run against a target vCenter appliance and limit the controls run to a single control
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password' --controls=VCEM-70-000001

# Run against a target vCenter appliance and limit the controls run that match a regex string
inspec exec C:\Inspec\Profiles\vmware-vcsa-7.0-stig-baseline -t ssh://root@10.1.1.1 --password 'password' --controls=/VCEM-70/
```

The arguments provided in the example can be combined as needed.

For more options, see [InSpec Executable](https://docs.chef.io/inspec/cli/#exec).

## References

For the full InSpec documentation, see the [InSpec Installation Instructions](https://docs.chef.io/inspec/install/).
For Cinc Auditor, see the [Cinc Project Download Page](https://cinc.sh/download/).