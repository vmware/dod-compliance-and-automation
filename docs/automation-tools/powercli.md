# PowerShell/PowerCLI

## Overview

PowerCLI is a command-line interface for managing and automating all aspects of vSphere management, including networking, storage, VMs, guest OS, and more.
PowerCLI functions as a collection of PowerShell modules that contain more than 700 cmdlets (commands) to manage VMware infrastructure.

PowerCLI runs on top of PowerShell, which is a cross-platform task automation and configuration management framework. It consists of a command-line shell and a scripting language.
PowerCLI uses PowerShell’s basic syntax and concepts.

## Prerequisites

* PowerShell version 5.1 or later is required to run PowerCLI cmdlets.
* PowerShell comes installed on Windows and Windows Server by default.
* For Linux and MAC PowerShell must be installed.

For more information, see the [PowerCLI Compatability matrixes](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/vmware-powercli-compatibility-matrix.html).

## Installation

### Online
PowerCLI can be installed directly from the [PowerShell Gallery](https://www.powershellgallery.com/).

```powershell
# Run the following command from a PowerShell prompt
Install-Module -Name VMware.PowerCLI
```

### Offline
Download the .zip file with the latest released PowerCLI version from [here](https://developer.broadcom.com/tools/vmware-powercli/latest).

```powershell
# To retrieve the folder(s) on your machine that contain PowerShell modules, run the following command.
$env:PSModulePath

# Extract the downloaded .zip file to one of the listed folders.

# Unblock the copied files
cd path_to_powershell_modules_folder Get-ChildItem * -Recurse | Unblock-File

# Verify if the PowerCLI module is available on your system.
Get-Module -Name VMware.PowerCLI -ListAvailable
```

## Basic Usage
PowerCLI includes cmdlets to connect to supported VMware products. This must be done before any other PowerCLI cmdlets can be run successfully.

Connect to vCenter or ESXi directly:

```powershell
# Connects to a vSphere server by using the User and Password parameters.
Connect-VIServer -Server 10.23.112.235 -Protocol https -User admin -Password pass

# Connects to a vSphere server by using a credential object.
$cred = Get-Credential
Connect-VIServer -Server 10.23.112.235 -Protocol https -Credential $cred
```

## References

For the full PowerCLI documentation, see the [PowerCLI Installation Guide](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli.html)
