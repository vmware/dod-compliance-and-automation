<# 
  .SYNOPSIS 
    The VMware Cloud Foundation vSphere Virtual Machine STIG remediation script remediates VMs
    against the VMware Cloud Foundation vSphere VM STIG Readiness Guide Version 1 Release 1.
  .DESCRIPTION
    The VMware Cloud Foundation vSphere Virtual Machine STIG remediation script remediates VMs
    against the VMware Cloud Foundation vSphere VM STIG Readiness Guide Version 1 Release 1.

    It is designed to connect to a target vCenter and remediate a single VM, all VMs in a
    cluster, or all VMs in a vCenter. Individual STIG rules can be enabled or disabled in the
    provided variables file in the $rulesenabled hash table.

    The script will output a Powershell transcript as well as a JSON report with a summary of
    actions performed to the provided report directory.

  .NOTES 
    File Name  : VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 
    Author     : Broadcom
    Version    : 1.0.0
    License    : Apache-2.0

    Minimum Requirements
    
    VCF PowerCLI               : 9.0.0.0
    VMware.VCF.STIG.Helpers    : 1.0.1
    Powershell                 : 5.1
    Powershell Core            : 7.3.4
    vCenter/ESX                : 9.0.x.x

    -Not all controls are remediated by this script. Please review the output and items skipped for
     manual remediation.
    -Some fixes will require a reboot of the host to take effect and will be displayed in vCenter as 
     reboot required.

  .LINK
    https://github.com/vmware/dod-compliance-and-automation

  .LINK
    https://knowledge.broadcom.com/external/article?legacyId=94398

  .INPUTS
    The VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1 file needs to be updated with the necessary variable values for the target environment prior to running.

    Pipeline input not accepted.

  .OUTPUTS
    Powershell Transcript txt file and a summary report JSON file.

  .PARAMETER vccred
  Enter the pscredential variable name to use for authentication to vCenter. This should be run before the script for example: $cred = Get-Credential
  .PARAMETER NoSafetyChecks
  If specified, this switch parameter will disable "safety" checks to determine supported versions of Powershell modules, vCenter, and ESX are the targets and if not abort the script.
  .PARAMETER RevertToDefault
  If specified, this switch parameter will inform the script to instead of hardening the target VMs, revert to the default out of the box settings.
  .PARAMETER GlobalVarsFile
  Global Variables file name. Must be in the same directory as the script.
  .PARAMETER RemediationVarsFile
  Remediation Variables file name. Must be in the same directory as the script.

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 -vccred $vccred

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks -RevertToDefault

#>

[CmdletBinding()]
param (
  [Parameter(Mandatory=$true,
  HelpMessage="Provide Powershell credential object for use in connecting to the target vCenter server.")]
  [pscredential]$vccred,
  [Parameter(Mandatory=$false,
  HelpMessage="Skip safety checks to verify PowerCLI, vCenter, and ESX versions before running script.")]
  [switch]$NoSafetyChecks = $false,
  [Parameter(Mandatory=$false,
  HelpMessage="When specified the script will revert all settings back to the known default 'Out of the Box' values.")]
  [switch]$RevertToDefault = $false,
  [Parameter(Mandatory=$false,
  HelpMessage="Global Variables file name. Must be in the same directory as the script.")]
  [string]$GlobalVarsFile = "VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1",
  [Parameter(Mandatory=$false,
  HelpMessage="Remediation Variables file name. Must be in the same directory as the script.")]
  [string]$RemediationVarsFile = "VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1"
)

# Script Variables
$STIGVersion = "STIG Readiness Guide Version 1 Release 1"
$ReportNamePrefix = "VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation"
$MinimumPowerCLIVersion = "9.0.0"
$MinimumVCVersion = "9.0.0"
$MaximumVCVersion = "9.0.0"

# Initialize report variables
$changedcount = 0
$unchangedcount= 0
$skipcount = 0
$failedcount = 0

# Determine correct directory separate for Windows or Linux
$DirectorySep = [System.IO.Path]::DirectorySeparatorChar

# Import Variables from Global and Remediation variables files
$ScriptPath = (Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path)
$GlobalVariables = $ScriptPath + $DirectorySep + $GlobalVarsFile
Write-Message -Level "INFO" -Message "Importing Global Variables from: $GlobalVariables"
. $GlobalVariables
$RemediationVariables = $ScriptPath + $DirectorySep + $RemediationVarsFile
Write-Message -Level "INFO" -Message "Importing Remediation Variables from: $RemediationVariables"
. $RemediationVariables

# Setup reporting and start transcript
Try{
  If($reportpath){
    # Capture Date variable
    $Date = Get-Date
    # Start Transcript
    $TranscriptName = $reportpath + $DirectorySep + $ReportNamePrefix + "_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
    Write-Message -Level "INFO" -Message "Starting Powershell Transcript at $TranscriptName"
    Start-Transcript -Path $TranscriptName
    # Results file name for output to json
    $resultjson = $reportpath + $DirectorySep + $ReportNamePrefix + "_Results" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"
  }
  Else{
    Write-Message -Level "ERROR" -Message "No report path specified in $GlobalVariables. Please provide a report path and rerun script."
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to start transcript."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test PowerCLI Version
Try{
  Write-Header -Title "VMware vSphere VM STIG Remediation" -STIGVersion $STIGVersion -name $vcenter
  If($RevertToDefault){
    Write-Message -Level "WARNING" -Message "Revert to default values option specified. Hardening will be removed and stored to the default values."
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run PowerCLI version check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test PowerCLI Version
Try{
  If($NoSafetyChecks){
    Write-Message -Level "SKIPPED" -Message "No safety check enabled. Skipping PowerCLI version check."
  }
  Else{
    Test-PowerCLI -MinimumPowerCLIVersion $MinimumPowerCLIVersion
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run PowerCLI version check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Connect to vCenter
Try{
  Write-Message -Level "INFO" -Message "Connecting to vCenter: $vcenter"
  Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to connect to vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test vCenter Version
Try{
  If($NoSafetyChecks){
    Write-Message -Level "SKIPPED" -Message "No safety check enabled. Skipping vCenter version check."
  }
  Else{
    Test-vCenter -MinimumVCVersion $MinimumVCVersion -MaximumVCVersion $MaximumVCVersion
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run vCenter safe check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Gather Info
Try{
  Write-Message -Level "INFO" -Message "Gathering info on target VMs in vCenter: $vcenter"
  If($vmname){
    $vms = Get-VM -Name $vmname -ErrorAction Stop | Sort-Object Name 
    ForEach($vm in $vms){
      Write-Message -Level "INFO" -Message "Found target VM: $($vm.name)."
    }
  }
  ElseIf($cluster){
    $vms = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VM -ErrorAction Stop | Sort-Object Name
    ForEach($vm in $vms){
      Write-Message -Level "INFO" -Message "Found target VM: $($vm.name)."
    }
  }
  ElseIf($allvms){
    $vms = Get-VM -ErrorAction Stop | Sort-Object Name
    ForEach($vm in $vms){
      Write-Message -Level "INFO" -Message "Found target VM: $($vm.name)."
    }
  }
  Else{
    Write-Message -Level "ERROR" -Message "No targets specified for remediation detected in $GlobalVariables. Exiting script."
    Write-Message -Level "INFO" -Message "Disconnecting from vCenter Server: $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to gather information on target hosts in vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message $_.Exception
  Write-Message -Level "INFO" -Message "Disconnecting from vCenter Server: $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Exit -1
}

# VCFV-9X-000181 isolation.tools.copy.disable
Try{
	$STIGID = "VCFV-9X-000181"
	$Title = "Virtual machines (VMs) must have copy operations disabled."
  If($rulesenabled.VCFV9X000181){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoToolsCopyDisable.Keys
        $value = $stigsettings.isoToolsCopyDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoToolsCopyDisable.Keys
        $value = $defaultsettings.isoToolsCopyDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000196 isolation.tools.dnd.disable
Try{
	$STIGID = "VCFV-9X-000196"
	$Title = "Virtual machines (VMs) must have drag and drop operations disabled."
  If($rulesenabled.VCFV9X000196){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoToolsDndDisable.Keys
        $value = $stigsettings.isoToolsDndDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoToolsDndDisable.Keys
        $value = $defaultsettings.isoToolsDndDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000197 isolation.tools.paste.disable
Try{
	$STIGID = "VCFV-9X-000197"
	$Title = "Virtual machines (VMs) must have paste operations disabled."
  If($rulesenabled.VCFV9X000197){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoToolsPasteDisable.Keys
        $value = $stigsettings.isoToolsPasteDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoToolsPasteDisable.Keys
        $value = $defaultsettings.isoToolsPasteDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000198 isolation.tools.diskShrink.disable
Try{
	$STIGID = "VCFV-9X-000198"
	$Title = "Virtual machines (VMs) must have virtual disk shrinking disabled."
  If($rulesenabled.VCFV9X000198){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoToolsDiskShrinkDisable.Keys
        $value = $stigsettings.isoToolsDiskShrinkDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoToolsDiskShrinkDisable.Keys
        $value = $defaultsettings.isoToolsDiskShrinkDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000199 isolation.tools.diskWiper.disable
Try{
	$STIGID = "VCFV-9X-000199"
	$Title = "Virtual machines (VMs) must have virtual disk wiping disabled."
  If($rulesenabled.VCFV9X000199){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoToolsDiskWiperDisable.Keys
        $value = $stigsettings.isoToolsDiskWiperDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoToolsDiskWiperDisable.Keys
        $value = $defaultsettings.isoToolsDiskWiperDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000200 RemoteDisplay.maxConnections
Try{
	$STIGID = "VCFV-9X-000200"
	$Title = "Virtual machines (VMs) must limit console sharing."
  If($rulesenabled.VCFV9X000200){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.remoteDisplayMaxConn.Keys
        $value = [String]$stigsettings.remoteDisplayMaxConn.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on VM: $($vm.name). Adding setting $name and configuring value to $value."
          $vm | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.remoteDisplayMaxConn.Keys
        $value = [String]$defaultsettings.remoteDisplayMaxConn.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on VM: $($vm.name). Adding setting $name and configuring value to $value."
          $vm | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000201 tools.setinfo.sizeLimit
Try{
	$STIGID = "VCFV-9X-000201"
	$Title = "Virtual machines (VMs) must limit informational messages from the virtual machine to the VMX file."
  If($rulesenabled.VCFV9X000201){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.toolsSetinfoSizelimit.Keys
        $value = [String]$stigsettings.toolsSetinfoSizelimit.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.toolsSetinfoSizelimit.Keys
        $value = [String]$defaultsettings.toolsSetinfoSizelimit.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000202 isolation.device.connectable.disable
Try{
	$STIGID = "VCFV-9X-000202"
	$Title = "Virtual machines (VMs) must prevent unauthorized removal, connection, and modification of devices."
  If($rulesenabled.VCFV9X000202){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.isoDevConnDisable.Keys
        $value = $stigsettings.isoDevConnDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.isoDevConnDisable.Keys
        $value = $defaultsettings.isoDevConnDisable.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000203 tools.guestlib.enableHostInfo
Try{
	$STIGID = "VCFV-9X-000203"
	$Title = "Virtual machines (VMs) must not be able to obtain host information from the hypervisor."
  If($rulesenabled.VCFV9X000203){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.toolsGuestlibEnablehostinfo.Keys
        $value = $stigsettings.toolsGuestlibEnablehostinfo.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.toolsGuestlibEnablehostinfo.Keys
        $value = $defaultsettings.toolsGuestlibEnablehostinfo.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000204 sched.mem.pshare.salt
Try{
	$STIGID = "VCFV-9X-000204"
	$Title = "Virtual machines (VMs) must have shared salt values disabled."
  If($rulesenabled.VCFV9X000204){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = "sched.mem.pshare.salt"
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          Write-Message -Level "CHANGED" -Message "Setting $name exists and is set to $($asetting.value) on VM: $($vm.name). Removing setting."
          $asetting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = "sched.mem.pshare.salt"
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          Write-Message -Level "CHANGED" -Message "Setting $name exists and is set to $($asetting.value) on VM: $($vm.name). Removing setting."
          $asetting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      } 
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000205 ethernet*.filter*.name*
Try{
	$STIGID = "VCFV-9X-000205"
	$Title = 'Virtual machines (VMs) must disable access through the "dvfilter" network Application Programming Interface (API).'
  If($rulesenabled.VCFV9X000205){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = "ethernet*.filter*.name*"
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          Write-Message -Level "FAILED" -Message "Setting $name exists and is set to $($asetting.value) on VM: $($vm.name). Removing setting or document as an exception."
          $failedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = "ethernet*.filter*.name*"
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          Write-Message -Level "CHANGED" -Message "Setting $name exists and is set to $($asetting.value) on VM: $($vm.name). Removing setting."
          $asetting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      } 
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000206 tools.guest.desktop.autolock
Try{
	$STIGID = "VCFV-9X-000206"
	$Title = "Virtual machines (VMs) must be configured to lock when the last console connection is closed."
  If($rulesenabled.VCFV9X000206){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.toolsGuestDesktopAutolock.Keys
        $value = $stigsettings.toolsGuestDesktopAutolock.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.toolsGuestDesktopAutolock.Keys
        $value = $defaultsettings.toolsGuestDesktopAutolock.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000207 mks.enable3d
Try{
	$STIGID = "VCFV-9X-000207"
	$Title = "Virtual machines (VMs) must disable 3D features when not required."
  If($rulesenabled.VCFV9X000207){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.mksEnable3d.Keys
        $value = $stigsettings.mksEnable3d.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.mksEnable3d.Keys
        $value = $defaultsettings.mksEnable3d.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000208 vMotion Encryption
Try{
	$STIGID = "VCFV-9X-000208"
	$Title = "Virtual machines (VMs) must enable encryption for vMotion."
  If($rulesenabled.VCFV9X000208){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        If($vm.extensiondata.Config.MigrateEncryption -eq $stigsettings.vmotionEncryption){
          Write-Message -Level "PASS" -Message "vMotion encryption set correctly on VM: $($vm.name) to $($vm.extensiondata.Config.MigrateEncryption)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "vMotion encryption set incorrectly on VM: $($vm.name) to $($vm.extensiondata.Config.MigrateEncryption)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.MigrateEncryption = New-object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
          $config.MigrateEncryption = "$($stigsettings.vmotionEncryption)"
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        If($vm.extensiondata.Config.MigrateEncryption -eq $defaultsettings.vmotionEncryption){
          Write-Message -Level "PASS" -Message "vMotion encryption set correctly on VM: $($vm.name) to $($vm.extensiondata.Config.MigrateEncryption)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "vMotion encryption set incorrectly on VM: $($vm.name) to $($vm.extensiondata.Config.MigrateEncryption)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.MigrateEncryption = New-object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
          $config.MigrateEncryption = "$($defaultsettings.vmotionEncryption)"
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }     
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000209 FT Encryption
Try{
	$STIGID = "VCFV-9X-000209"
	$Title = "Virtual machines (VMs) must enable encryption for Fault Tolerance."
  If($rulesenabled.VCFV9X000209){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        If($vm.extensiondata.Config.FtEncryptionMode -eq $stigsettings.ftEncryption){
          Write-Message -Level "PASS" -Message "Fault tolerance encryption set correctly on VM: $($vm.name) to $($vm.extensiondata.Config.FtEncryptionMode)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Fault tolerance encryption set incorrectly on VM: $($vm.name) to $($vm.extensiondata.Config.FtEncryptionMode)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
          $config.FT = "$($stigsettings.FtEncryptionMode)"
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        If($vm.extensiondata.Config.FtEncryptionMode -eq $stigsettings.vmotionEncryption){
          Write-Message -Level "PASS" -Message "Fault tolerance encryption set correctly on VM: $($vm.name) to $($vm.extensiondata.Config.FtEncryptionMode)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Fault tolerance encryption set incorrectly on VM: $($vm.name) to $($vm.extensiondata.Config.FtEncryptionMode)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
          $config.FT = "$($defaultsettings.FtEncryptionMode)"
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }     
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000210 log.rotateSize
Try{
	$STIGID = "VCFV-9X-000210"
	$Title = "Virtual machines (VMs) must configure log size."
  If($rulesenabled.VCFV9X000210){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.logRotateSize.Keys
        $value = [String]$stigsettings.logRotateSize.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.logRotateSize.Keys
        $value = [String]$defaultsettings.logRotateSize.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000211 log.keepOld
Try{
	$STIGID = "VCFV-9X-000211"
	$Title = "Virtual machines (VMs) must configure log retention."
  If($rulesenabled.VCFV9X000211){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        $name = $stigsettings.logKeepOld.Keys
        $value = [String]$stigsettings.logKeepOld.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name). The default value is compliant if the setting does not exist."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        $name = $defaultsettings.logKeepOld.Keys
        $value = [String]$defaultsettings.logKeepOld.Values
        ## Checking to see if current setting exists
        If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on VM: $($vm.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name is incorrectly set to $($asetting.value) on VM: $($vm.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "Setting $name does not exist on VM: $($vm.name) which is the default state."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000212 Enabling Logging
Try{
	$STIGID = "VCFV-9X-000212"
	$Title = "Virtual machines (VMs) must enable logging."
  If($rulesenabled.VCFV9X000212){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vm in $vms){
        If($vm.ExtensionData.Config.Flags.EnableLogging -eq $stigsettings.enableLogging){
          Write-Message -Level "PASS" -Message "Enable logging set correctly on VM: $($vm.name) to $($vm.ExtensionData.Config.Flags.EnableLogging)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Enable logging set incorrectly on VM: $($vm.name) to $($vm.ExtensionData.Config.Flags.EnableLogging)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
          $config.Flags.enableLogging = $stigsettings.enableLogging
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vm in $vms){
        If($vm.ExtensionData.Config.Flags.EnableLogging -eq $defaultsettings.enableLogging){
          Write-Message -Level "PASS" -Message "Enable logging set correctly on VM: $($vm.name) to $($vm.ExtensionData.Config.Flags.EnableLogging)."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Enable logging set incorrectly on VM: $($vm.name) to $($vm.ExtensionData.Config.Flags.EnableLogging)."
          $vmv = $vm | Get-View -ErrorAction Stop
          $config = new-object VMware.Vim.VirtualMachineConfigSpec
          $config.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
          $config.Flags.enableLogging = $defaultsettings.enableLogging
          $vmv.ReconfigVM($config)
          $changedcount++
        }
      }     
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000213 Indepedent non-persistent disks
Try{
	$STIGID = "VCFV-9X-000213"
	$Title = "Virtual machines (VMs) must not use independent, nonpersistent disks."
  If($rulesenabled.VCFV9X000213){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $indDiskExceptions = $envstigsettings.indDiskExceptions
      ForEach($vm in $vms){
        $indnonpdisks = $vm | Get-HardDisk | Where-Object {$_.Persistence -eq "IndependentNonPersistent"} | Select-Object Name,Persistence,Filename
        If($indnonpdisks){
          If($indDiskExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Independent nonpersistent disk detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "FAIL" -Message "Independent nonpersistent disk detected on VM: $($vm.name). Investigate VM and determine if the disks need to be removed and manually remediate."
            $failedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No independent nonpersistent disks detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $indDiskExceptions = $envstigsettings.indDiskExceptions
      ForEach($vm in $vms){
        $indnonpdisks = $vm | Get-HardDisk | Where-Object {$_.Persistence -eq "IndependentNonPersistent"} | Select-Object Name,Persistence,Filename
        If($indnonpdisks){
          If($indDiskExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Independent nonpersistent disk detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "FAIL" -Message "Independent nonpersistent disk detected on VM: $($vm.name). Investigate VM and determine if the disks need to be removed and manually remediate."
            $failedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No independent nonpersistent disks detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }      
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000214 Floppy Drive
Try{
	$STIGID = "VCFV-9X-000214"
	$Title = "Virtual machines (VMs) must remove unneeded floppy devices."
  If($rulesenabled.VCFV9X000214){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $floppyExceptions = $envstigsettings.floppyExceptions
      ForEach($vm in $vms){
        $floppies = $vm | Get-FloppyDrive
        If($floppies){
          If($floppyExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Floppy drive detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing floppy drive on VM: $($vm.name)."
              $floppies | Remove-FloppyDrive -Confirm:$false
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove floppy drive on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No floppy drives detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $floppyExceptions = $envstigsettings.floppyExceptions
      ForEach($vm in $vms){
        $floppies = $vm | Get-FloppyDrive
        If($floppies){
          If($floppyExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Floppy drive detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing floppy drive on VM: $($vm.name)."
              $floppies | Remove-FloppyDrive -Confirm:$false
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove floppy drive on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No floppy drives detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }     
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000215 CD/DVD Media
Try{
	$STIGID = "VCFV-9X-000215"
	$Title = "Virtual machines (VMs) must remove unneeded CD/DVD devices."
  If($rulesenabled.VCFV9X000215){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $cddvdExceptions = $envstigsettings.cddvdExceptions
      ForEach($vm in $vms){
        $media = $vm | Get-CDDrive | Where-Object {$_.extensiondata.connectable.connected -eq $true}
        If($media){
          If($cddvdExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Connected CD/DVD media detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Removing connected CD/DVD media on VM: $($vm.name)."
            $vm | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No connected CD/DVD media on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $cddvdExceptions = $envstigsettings.cddvdExceptions
      ForEach($vm in $vms){
        $media = $vm | Get-CDDrive | Where-Object {$_.extensiondata.connectable.connected -eq $true}
        If($media){
          If($cddvdExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Connected CD/DVD media detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Removing connected CD/DVD media on VM: $($vm.name)."
            $vm | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No connected CD/DVD media on VM: $($vm.name)."
          $unchangedcount++
        }
      }    
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000216 Parallel devices
Try{
	$STIGID = "VCFV-9X-000216"
	$Title = "Virtual machines (VMs) must remove unneeded parallel devices."
  If($rulesenabled.VCFV9X000216){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $parallelExceptions = $envstigsettings.parallelExceptions
      ForEach($vm in $vms){
        $paralleldevs = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"
        If($paralleldevs){
          If($parallelExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Parallel device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing parallel device on VM: $($vm.name)."
              $pport = $vm.ExtensionData.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "Parallel"}
              $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
              $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
              $spec.DeviceChange[-1].device = $pport
              $spec.DeviceChange[-1].operation = "remove"
              $vm.ExtensionData.ReconfigVM($spec)
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove parallel device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No parallel devices detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $parallelExceptions = $envstigsettings.parallelExceptions
      ForEach($vm in $vms){
        $paralleldevs = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"
        If($paralleldevs){
          If($parallelExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Parallel device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing parallel device on VM: $($vm.name)."
              $pport = $vm.ExtensionData.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "Parallel"}
              $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
              $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
              $spec.DeviceChange[-1].device = $pport
              $spec.DeviceChange[-1].operation = "remove"
              $vm.ExtensionData.ReconfigVM($spec)
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove parallel device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No parallel devices detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }    
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000217 Serial devices
Try{
	$STIGID = "VCFV-9X-000217"
	$Title = "Virtual machines (VMs) must remove unneeded serial devices."
  If($rulesenabled.VCFV9X000217){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $serialExceptions = $envstigsettings.serialExceptions
      ForEach($vm in $vms){
        $serialdevs = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"
        If($serialdevs){
          If($serialExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Serial device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing serial device on VM: $($vm.name)."
              $sport = $vm.ExtensionData.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "Serial"}
              $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
              $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
              $spec.DeviceChange[-1].device = $sport
              $spec.DeviceChange[-1].operation = "remove"
              $vm.ExtensionData.ReconfigVM($spec)
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove serial device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No serial devices detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $serialExceptions = $envstigsettings.serialExceptions
      ForEach($vm in $vms){
        $serialdevs = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"
        If($serialdevs){
          If($serialExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "Serial device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing serial device on VM: $($vm.name)."
              $sport = $vm.ExtensionData.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "Serial"}
              $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
              $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
              $spec.DeviceChange[-1].device = $sport
              $spec.DeviceChange[-1].operation = "remove"
              $vm.ExtensionData.ReconfigVM($spec)
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove serial device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No serial devices detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }   
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000218 USB devices
Try{
	$STIGID = "VCFV-9X-000218"
	$Title = "Virtual machines (VMs) must remove unneeded USB devices."
  If($rulesenabled.VCFV9X000218){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $usbExceptions = $envstigsettings.usbExceptions
      ForEach($vm in $vms){
        $usbcontrollers = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"
        If($usbcontrollers){
          If($usbExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "USB controller detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing USB controller on VM: $($vm.name)."
              $usbc = $vm.ExtensionData.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "USB"}
              $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
              $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
              $spec.DeviceChange[-1].device = $usbc
              $spec.DeviceChange[-1].operation = "remove"
              $vm.ExtensionData.ReconfigVM($spec)
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove USB controller on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++              
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No USB controller on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $usbExceptions = $envstigsettings.usbExceptions
      ForEach($vm in $vms){
        $usbcontrollers = $vm.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"
        If($usbcontrollers){
          If($usbExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "USB controller detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "USB controller detected on VM: $($vm.name)."
            $unchangedcount++
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No USB controller on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

# VCFV-9X-000219 DirectPath I/O devices
Try{
	$STIGID = "VCFV-9X-000219"
	$Title = "Virtual machines (VMs) must disable DirectPath I/O devices when not required."
  If($rulesenabled.VCFV9X000219){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $passthruExceptions = $envstigsettings.passthruExceptions
      ForEach($vm in $vms){
        $passthroughdev = $vm | Get-PassthroughDevice
        If($passthroughdev){
          If($passthruExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "DirectPath I/O passthrough device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing DirectPath I/O passthrough device on VM: $($vm.name)."
              $passthroughdev | Remove-PassthroughDevice -Confirm:$false
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove DirectPath I/O passthrough device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No DirectPath I/O passthrough device detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      $passthruExceptions = $envstigsettings.passthruExceptions
      ForEach($vm in $vms){
        $passthroughdev = $vm | Get-PassthroughDevice
        If($passthroughdev){
          If($passthruExceptions.Contains($vm.name)){
            Write-Message -Level "PASS" -Message "DirectPath I/O passthrough device detected on VM: $($vm.name). VM is present on the exceptions list."
            $unchangedcount++
          }
          Else{
            If($vm.PowerState -eq "PoweredOff"){
              Write-Message -Level "CHANGED" -Message "Removing DirectPath I/O passthrough device on VM: $($vm.name)."
              $passthroughdev | Remove-PassthroughDevice -Confirm:$false
              $changedcount++
            }
            Else{
              Write-Message -Level "FAIL" -Message "Cannot remove DirectPath I/O passthrough device on VM: $($vm.name) because it is powered on. Power off VM and run script again or manually remediate."
              $failedcount++
            }
          }
        }
        Else{
          Write-Message -Level "PASS" -Message "No DirectPath I/O passthrough device detected on VM: $($vm.name)."
          $unchangedcount++
        }
      }
    }
  }
  Else{
    Write-Message -Level "SKIPPED" -Message "Skipping disabled rule. STIG ID: $STIGID Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to remediate rule on $($vmhost.name). STIG ID:$STIGID Title: $Title"
  Write-Message -Level "ERROR" -Message $_.Exception
  $failedcount++
}

$summary = New-Object PSObject -Property ([ordered]@{
  "vcenter" = $vcenter
  "cluster" = $cluster
  "vms" = $vms.Name
  "allvms" = $allvms
  "reportpath" = $reportpath
  "ok" = $unchangedcount
  "changed" = $changedcount
  "skipped" = $skipcount
  "failed" = $failedcount
  "inputs" = $stigsettings
  "rulesenabled" = $rulesenabled
})

$summary = $summary | ConvertTo-Json
Write-Message -Level "INFO" -Message "Configuration Summary:"
Write-Message -Level "INFO" -Message $summary
Write-Message -Level "INFO" -Message "Remediation Complete"
Write-Message -Level "INFO" -Message "Disconnecting from vCenter: $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
Write-Message -Level "INFO" -Message "Stopping Powershell Transcript at $TranscriptName"
Stop-Transcript
Write-Message -Level "INFO" -Message "Generating JSON script report at $resultjson"
$summary | Out-File $resultjson
