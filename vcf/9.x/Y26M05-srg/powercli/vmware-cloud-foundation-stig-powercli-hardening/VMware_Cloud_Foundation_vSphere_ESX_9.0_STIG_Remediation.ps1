<# 
  .SYNOPSIS 
    The VMware Cloud Foundation vSphere ESX STIG remediation script remediates ESX hosts
    against the VMware Cloud Foundation vSphere ESX STIG Readiness Guide Version 1 Release 1.
  .DESCRIPTION
    The VMware Cloud Foundation vSphere ESX STIG remediation script remediates ESX hosts
    against the VMware Cloud Foundation vSphere ESX STIG Readiness Guide Version 1 Release 1.

    It is designed to connect to a target vCenter and remediate a single ESX host or target a
    cluster of hosts. Individual STIG rules can be enabled or disabled in the provided
    variables file in the $rulesenabled hash table.

    The script will output a Powershell transcript as well as a JSON report with a summary of
    actions performed to the provided report directory.

  .NOTES 
    File Name  : VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 
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
    -By default this script will enable the ESX firewall if disabled and also configure each enabled
     service to only be accessible by the IP ranges given. Please ensure the parameter values given 
     are correct for your environment before running so access is not lost.
    -Some fixes will require a reboot of the host to take effect and will be displayed in vCenter as 
     reboot required.
    -If the TLS Profile is configured using this script then host must be in maintenance mode in order
     for that task to run.

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
  If specified, this switch parameter will inform the script to instead of hardening the target ESX hosts, revert to the default out of the box settings.
  .PARAMETER GlobalVarsFile
  Global Variables file name. Must be in the same directory as the script.
  .PARAMETER RemediationVarsFile
  Remediation Variables file name. Must be in the same directory as the script.

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks -RevertToDefault

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
  [string]$RemediationVarsFile = "VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1"
)

# Script Variables
$STIGVersion = "STIG Readiness Guide Version 1 Release 1"
$ReportNamePrefix = "VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation"
$MinimumPowerCLIVersion = "9.0.0"
$MinimumVCVersion = "9.0.0"
$MaximumVCVersion = "9.0.0"
$MinimumESXVersion = "9.0.0"
$MaximumESXVersion = "9.0.0"

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
  Write-Header -Title "VMware vSphere ESX STIG Remediation" -STIGVersion $STIGVersion -name $vcenter
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
  Write-Message -Level "INFO" -Message "Gathering info on target ESX hosts in vCenter: $vcenter"
  If($hostname){
    $vmhosts = Get-VMHost -Name $hostname -ErrorAction Stop | Sort-Object Name
    $vmhostsv = $vmhosts | Get-View -ErrorAction Stop | Sort-Object Name 
    ForEach($vmhost in $vmhosts){
      Write-Message -Level "INFO" -Message "Found target host: $($vmhost.name)."
      If($NoSafetyChecks){
        Write-Message -Level "SKIPPED" -Message "No safety checks enabled. Skipping ESX version check on ESX host: $($vmhost.Name)."
      }
      Else{
        Test-ESX -VMHost $vmhost -MinimumESXVersion $MinimumESXVersion -MaximumESXVersion $MaximumESXVersion
      }
    }
  }
  ElseIf($cluster){
    $vmhosts = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object Name
    $vmhostsv = $vmhosts | Get-View | Sort-Object Name
    ForEach($vmhost in $vmhosts){
      Write-Message -Level "INFO" -Message "Found target host: $($vmhost.name)."
      If($NoSafetyChecks){
        Write-Message -Level "SKIPPED" -Message "No safety checks enabled. Skipping ESX version check on ESX host: $($vmhost.Name)."
      }
      Else{
        Test-ESX -VMHost $vmhost -MinimumESXVersion $MinimumESXVersion -MaximumESXVersion $MaximumESXVersion
      }
    }
  }
  Else{
    Write-Message -Level "INFO" -Message "No targets specified for remediation detected in $GlobalVariables. Exiting script."
    Exit
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to gather information on target hosts in vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message $_.Exception
  Write-Message -Level "INFO" -Message "Disconnecting from vCenter Server: $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Exit -1
}

# VCFE-9X-000005 Account Lock Failures
Try{
	$STIGID = "VCFE-9X-000005"
	$Title = "The ESX host must enforce the limit of three consecutive invalid logon attempts by a user."
  If($rulesenabled.VCFE9X000005){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.accountLockFailures.Keys
        $value = [string]$stigsettings.accountLockFailures.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.accountLockFailures.Keys
        $value = [string]$defaultsettings.accountLockFailures.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000006 Welcome banner
Try{
	$STIGID = "VCFE-9X-000006"
	$Title = "The ESX host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via the Direct Console User Interface (DCUI)."
  If($rulesenabled.VCFE9X000006){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = "Annotations.WelcomeMessage"
        $value = $welcomeBanner
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          $valuereplaced = $value.Replace("`n","").Replace("`r","").Replace(" ","")
          $asettingvaluereplaced = $asetting.value.Replace("`n","").Replace("`r","").Replace(" ","")
          If($asettingvaluereplaced -eq $valuereplaced){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set on Host: $($vmhost.name). Configuring value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.welcomeBanner.Keys
        $value = [string]$defaultsettings.welcomeBanner.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set on Host: $($vmhost.name). Configuring value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000010 Account Lock Failures
Try{
	$STIGID = "VCFE-9X-000010"
	$Title = "The ESX host client must be configured with an idle session timeout."
  If($rulesenabled.VCFE9X000010){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.hostClientTimeout.Keys
        $value = [string]$stigsettings.hostClientTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.hostClientTimeout.Keys
        $value = [string]$defaultsettings.hostClientTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000014 TLS Profiles
Try{
	$STIGID = "VCFE-9X-000014"
	$Title = "The ESX host must use DOD-approved encryption to protect the confidentiality of network sessions."
  If($rulesenabled.VCFE9X000014){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $tlscheckargs = $esxcli.system.tls.server.get.CreateArgs()
        $tlscheckargs.showprofiledefaults = $true
        $tlscheckargs.showcurrentbootprofile = $true
        $results = $esxcli.system.tls.server.get.invoke($tlscheckargs) | Select-Object -ExpandProperty Profile
        If($results -eq $stigsettings.tlsServerProfile ){
          Write-Message -Level "PASS" -Message "TLS server profile configured correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          If($vmhost.ConnectionState -eq "Maintenance"){
            Write-Message -Level "CHANGED" -Message "Maintenance Mode detected. Configuring TLS server profile to $($stigsettings.tlsServerProfile) on Host: $($vmhost.name)."
            $tlsargs = $esxcli.system.tls.server.set.CreateArgs()
            $tlsargs.profile = $stigsettings.tlsServerProfile
            $esxcli.system.tls.server.set.invoke($tlsargs)
            $changedcount++
          }Else{
            Write-Message -Level "SKIPPED" -Message "Host: $($vmhost.name) is not in Maintenance Mode. Skipping control STIG ID:$STIGID for host."
            $skipcount++
          }
        }
      }
    }
    Else{
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $tlscheckargs = $esxcli.system.tls.server.get.CreateArgs()
        $tlscheckargs.showprofiledefaults = $true
        $tlscheckargs.showcurrentbootprofile = $true
        $results = $esxcli.system.tls.server.get.invoke($tlscheckargs) | Select-Object -ExpandProperty Profile
        If($results -eq $defaultsettings.tlsServerProfile ){
          Write-Message -Level "PASS" -Message "TLS server profile configured correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          If($vmhost.ConnectionState -eq "Maintenance"){
            Write-Message -Level "CHANGED" -Message "Maintenance Mode detected. Configuring TLS server profile to $($defaultsettings.tlsServerProfile) on Host: $($vmhost.name)."
            $tlsargs = $esxcli.system.tls.server.set.CreateArgs()
            $tlsargs.profile = $defaultsettings.tlsServerProfile
            $esxcli.system.tls.server.set.invoke($tlsargs)
            $changedcount++
          }Else{
            Write-Message -Level "SKIPPED" -Message "Host: $($vmhost.name) is not in Maintenance Mode. Skipping control STIG ID:$STIGID for host."
            $skipcount++
          }
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

# VCFE-9X-000015 Account Lock Failures
Try{
	$STIGID = "VCFE-9X-000015"
	$Title = "The ESX host must produce audit records containing information to establish what type of events occurred."
  If($rulesenabled.VCFE9X000015){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.logLevel.Keys
        $value = [string]$stigsettings.logLevel.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.logLevel.Keys
        $value = [string]$defaultsettings.logLevel.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000035 Password Complexity
Try{
	$STIGID = "VCFE-9X-000035"
	$Title = "The ESX host must enforce password complexity by configuring a password quality policy."
  If($rulesenabled.VCFE9X000035){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.passwordComplexity.Keys
        $value = [string]$stigsettings.passwordComplexity.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.passwordComplexity.Keys
        $value = [string]$defaultsettings.passwordComplexity.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000042 Password Max Days
Try{
	$STIGID = "VCFE-9X-000042"
	$Title = "The ESX host must enforce a 90-day maximum password lifetime restriction."
  If($rulesenabled.VCFE9X000042){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.passwordMaxDays.Keys
        $value = [string]$stigsettings.passwordMaxDays.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.passwordMaxDays.Keys
        $value = [string]$defaultsettings.passwordMaxDays.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000046 Managed Object Browser
Try{
	$STIGID = "VCFE-9X-000046"
	$Title = "The ESX host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB)."
  If($rulesenabled.VCFE9X000046){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.enableMob.Keys
        $value = [System.Convert]::ToBoolean([String]$stigsettings.enableMob.Values)
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.enableMob.Keys
        $value = [System.Convert]::ToBoolean([String]$defaultsettings.enableMob.Values)
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000048 Active Directory
Try{
	$STIGID = "VCFE-9X-000048"
	$Title = "The ESX host must uniquely identify and must authenticate organizational users by using Active Directory."
  If($rulesenabled.VCFE9X000048){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000064 Password Max Days
Try{
	$STIGID = "VCFE-9X-000064"
	$Title = "The ESX host must disable Inter-Virtual Machine (VM) Transparent Page Sharing."
  If($rulesenabled.VCFE9X000064){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.shareForceSalting.Keys
        $value = [string]$stigsettings.shareForceSalting.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.shareForceSalting.Keys
        $value = [string]$defaultsettings.shareForceSalting.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000066 Password Max Days
Try{
	$STIGID = "VCFE-9X-000066"
	$Title = "The ESX host must disable Inter-Virtual Machine (VM) Transparent Page Sharing."
  If($rulesenabled.VCFE9X000066){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.shellIntTimeout.Keys
        $value = [string]$stigsettings.shellIntTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.shellIntTimeout.Keys
        $value = [string]$defaultsettings.shellIntTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000082 Secure Boot enforcement for config encryption
Try{
	$STIGID = "VCFE-9X-000082"
	$Title = "The ESX host must enable Secure Boot enforcement for configuration encryption."
  If($rulesenabled.VCFE9X000082){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.settings.encryption.get.invoke()
        If($results.RequireSecureBoot -eq [String]$stigsettings.secureBootEnforcement){
          Write-Message -Level "PASS" -Message "Secure Boot enforcement for configuration encryption set correctly to $($results.RequireSecureBoot) on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring Secure Boot enforcement for configuration encryption on Host: $($vmhost.name)."
          $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
          $sbarg.mode = "TPM"
          $sbarg.requiresecureboot = $stigsettings.secureBootEnforcement
          $esxcli.system.settings.encryption.set.Invoke($sbarg)
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.settings.encryption.get.invoke()
        If($results.RequireSecureBoot -eq [String]$defaultsettings.secureBootEnforcement){
          Write-Message -Level "PASS" -Message "Secure Boot enforcement for configuration encryption set correctly to $($results.RequireSecureBoot) on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring Secure Boot enforcement for configuration encryption on Host: $($vmhost.name)."
          $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
          $sbarg.requiresecureboot = $defaultsettings.secureBootEnforcement
          $esxcli.system.settings.encryption.set.Invoke($sbarg)
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

# VCFE-9X-000091 Secure Boot
Try{
	$STIGID = "VCFE-9X-000091"
	$Title = "The ESX host must enable Secure Boot."
  If($rulesenabled.VCFE9X000091){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $uefisecureboot = $vmhost.ExtensionData.Capability.UefiSecureBoot
        If($uefisecureboot -eq $stigsettings.uefiSecureBoot){
          Write-Message -Level "PASS" -Message "UEFI Secureboot detected as $uefisecureboot on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "SKIPPED" -Message "UEFI Secureboot detected as NOT enabled on Host: $($vmhost.name). This rule must be remediated by enabling Secureboot in the servers firmware."
          $skipcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $uefisecureboot = $vmhost.ExtensionData.Capability.UefiSecureBoot
        If($uefisecureboot -eq $stigsettings.uefiSecureBoot){
          Write-Message -Level "PASS" -Message "UEFI Secureboot detected as $uefisecureboot on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "SKIPPED" -Message "UEFI Secureboot detected as NOT enabled on Host: $($vmhost.name). This rule must be remediated by enabling Secureboot in the servers firmware."
          $skipcount++
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

# VCFE-9X-000096 SSH Disabled
Try{
	$STIGID = "VCFE-9X-000096"
	$Title = "The ESX host must disable remote access to the information system by disabling Secure Shell (SSH)."
  If($rulesenabled.VCFE9X000096){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    $servicename = "SSH"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
        If($vmhostservice.Running -ne $stigsettings.serviceSshEnabled -or $vmhostservice.Policy -ne $stigsettings.serviceSshPolicy){
          Write-Message -Level "CHANGED" -Message "Stopping and disabling service: $servicename on Host: $($vmhost.name)."
          $vmhostservice | Set-VMHostService -Policy $stigsettings.serviceSshPolicy -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Service: $servicename is disabled on Host: $($vmhost.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
        If($vmhostservice.Running -ne $defaultsettings.serviceSshEnabled -or $vmhostservice.Policy -ne $defaultsettings.serviceSshPolicy){
          Write-Message -Level "CHANGED" -Message "Starting and enabling service: $servicename on Host: $($vmhost.name)."
          $vmhostservice | Set-VMHostService -Policy $defaultsettings.serviceSshPolicy -Confirm:$false -ErrorAction Stop
          $vmhostservice | Start-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Service: $servicename is enabled on Host: $($vmhost.name)."
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

# VCFE-9X-000108 Account Unlock Time
Try{
	$STIGID = "VCFE-9X-000108"
	$Title = "The ESX host must enforce an unlock timeout of 15 minutes after a user account is locked out."
  If($rulesenabled.VCFE9X000108){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.accountUnlockTime.Keys
        $value = [string]$stigsettings.accountUnlockTime.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.accountUnlockTime.Keys
        $value = [string]$defaultsettings.accountUnlockTime.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000110 Audit Record Capacity
Try{
	$STIGID = "VCFE-9X-000110"
	$Title = "The ESX host must allocate audit record storage capacity to store at least one week's worth of audit records."
  If($rulesenabled.VCFE9X000110){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.auditRecordStorageCap.Keys
        $value = [string]$stigsettings.auditRecordStorageCap.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.auditRecordStorageCap.Keys
        $value = [string]$defaultsettings.auditRecordStorageCap.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000111 Audit Record Capacity
Try{
	$STIGID = "VCFE-9X-000111"
	$Title = "The ESX host must off-load audit records onto a different system or media than the system being audited."
  If($rulesenabled.VCFE9X000111){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.auditRecordRemote.Keys
        $value = [string]$stigsettings.auditRecordRemote.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.auditRecordRemote.Keys
        $value = [string]$defaultsettings.auditRecordRemote.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000121 NTP
Try{
	$STIGID = "VCFE-9X-000121"
	$Title = "The ESX host must synchronize internal information system clocks to an authoritative time source."
  If($rulesenabled.VCFE9X000121){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($stigsettings.usePtpForTime){
      Write-Message -Level "SKIPPED" -Message "PTP use for time synch...skipping STIG ID: $STIGID Title: $Title"
    }
    Else{
      $servicename = "NTP Daemon"
      If($RevertToDefault -eq $false){
        $approvedNtpServers = $($envstigsettings.ntpServers)
        ForEach($vmhost in $vmhosts){
          $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
          $currentntpservers = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
          If($currentntpservers.count -eq "0"){
            Write-Message -Level "CHANGED" -Message "No NTP servers configured on Host: $($vmhost.name). Configuring the host with NTP servers: $approvedNtpServers"
            $vmhost | Add-VMHostNtpServer $approvedNtpServers -ErrorAction Stop
            $changedcount++
          }
          Else {
            # Remove NTP servers that are not in the ntpServers variable
            ForEach($ntpserver in $currentntpservers){
              If($approvedNtpServers.Contains($ntpserver)){
                Write-Message -Level "PASS" -Message "NTP Server: $ntpserver already configured on Host: $($vmhost.name)."
                $unchangedcount++
              }
              Else {
                Write-Message -Level "CHANGED" -Message "Removing unknown NTP Server: $ntpserver on Host: $($vmhost.name)."
                $vmhost | Remove-VMHostNtpServer -NtpServer $ntpserver -Confirm:$false -ErrorAction Stop
                $changedcount++
              }
            }
            # Add authorized NTP servers that are not currently configured
            ForEach($ntpserver in $approvedNtpServers){
              If(!($currentntpservers.Contains($ntpserver))){
                Write-Message -Level "CHANGED" -Message "Adding NTP Server: $ntpserver on Host: $($vmhost.name)."
                $vmhost | Add-VMHostNtpServer $ntpserver -ErrorAction Stop | Out-Null
                $changedcount++
              }
            }
          }
          If($vmhostservice.Running -ne $stigsettings.serviceNtpEnabled -or $vmhostservice.Policy -ne $stigsettings.serviceNtpPolicy){
            Write-Message -Level "CHANGED" -Message "Starting and enabling service: $servicename on Host: $($vmhost.name)."
            $vmhostservice | Set-VMHostService -Policy $stigsettings.serviceNtpPolicy -Confirm:$false -ErrorAction Stop | Out-Null
            $vmhostservice | Start-VMHostService -Confirm:$false -ErrorAction Stop | Out-Null
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Service: $servicename is running and enabled on Host: $($vmhost.name)."
            $unchangedcount++
          }
        }
      }
      Else{
        $approvedNtpServers = $($defaultsettings.ntpServers)
        ForEach($vmhost in $vmhosts){
          $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
          $currentntpservers = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
          If($currentntpservers.count -ne 0){
            Write-Message -Level "CHANGED" -Message "No NTP servers configured on Host: $($vmhost.name). Configuring the host with NTP servers: $approvedNtpServers"
            ForEach($ntpserver in $currentntpservers){
              Write-Message -Level "CHANGED" -Message "Removing non-default NTP Server: $ntpserver on Host: $($vmhost.name)."
              $vmhost | Remove-VMHostNtpServer -NtpServer $ntpserver -Confirm:$false -ErrorAction Stop
              $changedcount++
            }
          }
          Else {
            Write-Message -Level "PASS" -Message "No NTP servers configured on Host: $($vmhost.name)."
            $unchangedcount++
          }
          If($vmhostservice.Running -ne $defaultsettings.serviceNtpEnabled -or $vmhostservice.Policy -ne $defaultsettings.serviceNtpPolicy){
            Write-Message -Level "CHANGED" -Message "Starting and enabling service: $servicename on Host: $($vmhost.name)."
            $vmhostservice | Set-VMHostService -Policy $defaultsettings.serviceNtpPolicy -Confirm:$false -ErrorAction Stop | Out-Null
            $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop | Out-Null
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Service: $servicename is stopped and disabled on Host: $($vmhost.name)."
            $unchangedcount++
          }
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

# VCFE-9X-000130 VIB Acceptance
Try{
	$STIGID = "VCFE-9X-000130"
	$Title = "The ESX Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified."
  If($rulesenabled.VCFE9X000130){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.software.acceptance.get.Invoke()
        If($results -ne "CommunitySupported"){
          Write-Message -Level "PASS" -Message "VIB Acceptance level is set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring VIB Acceptance level to $($stigsettings.vibacceptlevel) on Host: $($vmhost.name)"
          $vibargs = $esxcli.software.acceptance.set.CreateArgs()
          $vibargs.level = $stigsettings.vibacceptlevel
          $esxcli.software.acceptance.set.Invoke($vibargs)
          $changedcount++
        }
      }
    }
    Else{
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.software.acceptance.get.Invoke()
        If($results -eq $defaultsettings.vibacceptlevel){
          Write-Message -Level "PASS" -Message "VIB Acceptance level is set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring VIB Acceptance level to $($defaultsettings.vibacceptlevel) on Host: $($vmhost.name)"
          $vibargs = $esxcli.software.acceptance.set.CreateArgs()
          $vibargs.level = $defaultsettings.vibacceptlevel
          $esxcli.software.acceptance.set.Invoke($vibargs)
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

# VCFE-9X-000138 iSCSI CHAP
Try{
	$STIGID = "VCFE-9X-000138"
	$Title = "The ESX host must enable bidirectional Challenge-Handshake Authentication Protocol (CHAP) authentication for Internet Small Computer Systems Interface (iSCSI) traffic."
  If($rulesenabled.VCFE9X000138){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000152 vMotion Separation
Try{
	$STIGID = "VCFE-9X-000152"
	$Title = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
  If($rulesenabled.VCFE9X000152){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
        ForEach($vmk in $vmks){
          If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereReplicationEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereReplicationNFCEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereBackupNFCEnabled -eq "True")){
            Write-Message -Level "ERROR" -Message "VMKernel: $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on Host: $($vmhost.name).  Investigate and separate functions to another network and VMKernel."
            $failedcount++
          }ElseIf($vmk.VMotionEnabled -eq "True"){
            Write-Message -Level "PASS" -Message "VMKernel: $($vmk.name) appears to have vMotion only enabled on Host: $($vmhost.name)."
            $unchangedcount++
          }
        }
      }
    }
    Else{
      Write-Message -Level "PASS" -Message "No action needed on this rule when ReverttoDefault is enabled."
      $unchangedcount++
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

# VCFE-9X-000181 DCUI Access
Try{
	$STIGID = "VCFE-9X-000181"
	$Title = "The ESX host must restrict access to the DCUI."
  If($rulesenabled.VCFE9X000181){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.dcuiAccess.Keys
        $value = [string]$stigsettings.dcuiAccess.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.dcuiAccess.Keys
        $value = [string]$defaultsettings.dcuiAccess.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000193 TPM Encryption
Try{
	$STIGID = "VCFE-9X-000193"
	$Title = "The ESX host must require TPM-based configuration encryption."
  If($rulesenabled.VCFE9X000193){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.settings.encryption.get.invoke()
        If($results.Mode -eq [String]$stigsettings.tpmConfigEncryption){
          Write-Message -Level "PASS" -Message "Configuration encryption set correctly to $($results.Mode) on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring configuration encryption on Host: $($vmhost.name)."
          $tpmencarg = $esxcli.system.settings.encryption.set.CreateArgs()
          $tpmencarg.mode = [String]$stigsettings.tpmConfigEncryption
          $esxcli.system.settings.encryption.set.Invoke($tpmencarg)
          $changedcount++
        }
      }
    }
    Else{
      Write-Message -Level "SKIPPED" -Message "No action needed on this rule when ReverttoDefault is enabled."
      $skipcount++
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

# VCFE-9X-000196 /etc/issue
Try{
	$STIGID = "VCFE-9X-000196"
	$Title = "The ESX host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via Secure Shell (SSH)."
  If($rulesenabled.VCFE9X000196){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $envstigsettings.issueBanner.Keys
        $value = [string]$envstigsettings.issueBanner.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.issueBanner.Keys
        $value = [string]$defaultsettings.issueBanner.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000197 SSH Banner
Try{
	$STIGID = "VCFE-9X-000197"
	$Title = "The ESX host Secure Shell (SSH) daemon must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
  If($rulesenabled.VCFE9X000197){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshBanner.Keys
      $value = [string]$stigsettings.sshBanner.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshBanner.Keys
      $value = [string]$defaultsettings.sshBanner.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000199 Shell Disabled
Try{
	$STIGID = "VCFE-9X-000199"
	$Title = "The ESX host must be configured to disable nonessential capabilities by disabling the ESXi shell."
  If($rulesenabled.VCFE9X000199){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    $servicename = "ESXi Shell"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
        If($vmhostservice.Running -ne $stigsettings.serviceShellEnabled -or $vmhostservice.Policy -ne $stigsettings.serviceShellPolicy){
          Write-Message -Level "CHANGED" -Message "Stopping and disabling service: $servicename on Host: $($vmhost.name)."
          $vmhostservice | Set-VMHostService -Policy $stigsettings.serviceShellPolicy -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Service: $servicename is disabled on Host: $($vmhost.name)."
          $unchangedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
        If($vmhostservice.Running -ne $defaultsettings.serviceShellEnabled -or $vmhostservice.Policy -ne $defaultsettings.serviceShellPolicy){
          Write-Message -Level "CHANGED" -Message "Stopping and disabling service: $servicename on Host: $($vmhost.name)."
          $vmhostservice | Set-VMHostService -Policy $defaultsettings.serviceShellPolicy -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Service: $servicename is disabled on Host: $($vmhost.name)."
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

# VCFE-9X-000200 Shell Timeout
Try{
	$STIGID = "VCFE-9X-000200"
	$Title = "The ESX host must automatically stop shell services after ten minutes."
  If($rulesenabled.VCFE9X000200){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.shellTimeout.Keys
        $value = [string]$stigsettings.shellTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.shellTimeout.Keys
        $value = [string]$defaultsettings.shellTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000201 DCUI Timeout
Try{
	$STIGID = "VCFE-9X-000201"
	$Title = "The ESX host must set a timeout to automatically end idle DCUI sessions after 10 minutes."
  If($rulesenabled.VCFE9X000201){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.dcuiTimeout.Keys
        $value = [string]$stigsettings.dcuiTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.dcuiTimeout.Keys
        $value = [string]$defaultsettings.dcuiTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000202 Syslog Log Directory
Try{
	$STIGID = "VCFE-9X-000202"
	$Title = "The ESX host must configure a persistent log location for all locally stored logs and audit records."
  If($rulesenabled.VCFE9X000202){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent
        If($results -eq $true ){
          Write-Message -Level "PASS" -Message "The Syslog.global.logDir value was detected as persistent on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "SKIPPED" -Message "The Syslog.global.logDir value was NOT detected as persistent and must be remediated manually on Host: $($vmhost.name)."
          $skipcount++
        }
      }
    }
    Else{
      Write-Message -Level "SKIPPED" -Message "No action needed on this rule when ReverttoDefault is enabled."
      $skipcount++
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

# VCFE-9X-000203 Management Isolation
Try{
	$STIGID = "VCFE-9X-000203"
	$Title = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating ESX management traffic."
  If($rulesenabled.VCFE9X000203){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000204 IP Storage Isolation
Try{
	$STIGID = "VCFE-9X-000204"
	$Title = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
  If($rulesenabled.VCFE9X000204){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000205 Lockdown Exception Users
Try{
	$STIGID = "VCFE-9X-000205"
	$Title = "The ESX host lockdown mode exception users list must be verified."
  If($rulesenabled.VCFE9X000205){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $ldexceptionusers = $envstigsettings.lockdownExceptionUsers
      $exceptioncount = 0
      $systemexceptionusers = @("da-user","mux_user","nsx-user")
      ForEach($vmhostv in $vmhostsv){
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
        $exceptions = $lockdown.QueryLockdownExceptions()
        If($exceptions){
          # Find the vcf-svc-* account name unique to each host
          $svcexceptionuser = $exceptions | Where-Object {$_ -match "svc-vcf-*"}
          # Combine system users, service user, and user defined user lists
          $ldexceptionusers = $ldexceptionusers + $systemexceptionusers + $svcexceptionuser
          ForEach($lduser in $exceptions){
            # Update exception users if an existing user is found that is not in the approved list
            If(!($ldexceptionusers.Contains($lduser))){
              Write-Message -Level "CHANGED" -Message "Removing exception user: $lduser found not in approved lockdown mode exception user list on Host: $($vmhostv.name)."
              $lockdown.UpdateLockdownExceptions($ldexceptionusers)
              $changedcount++
              $exceptioncount++
              # We only need to fix this once so breaking out of loop if fixed once
              break
            }
          }
          If($exceptioncount -eq 0){
            # Update exception users if a user is missing in the existing configuration that exists in the approved list
            ForEach($lduser in $ldexceptionusers){
              If(!($exceptions.Contains($lduser))){
                Write-Message -Level "CHANGED" -Message "Adding missing exception users in approved lockdown mode exception user list on Host: $($vmhostv.name)."
                $lockdown.UpdateLockdownExceptions($ldexceptionusers)
                $changedcount++
                $exceptioncount++
                break
              }
            }
            # If we land here then no differences were found between the existing configuration and the approved list
            If($exceptioncount -eq 0){
              Write-Message -Level "PASS" -Message "Exception users: $exceptions all in approved lockdown mode exception user list on Host: $($vmhostv.name)."
              $unchangedcount++
            }
          }
        }
        Else{
          # Update exception users if approved listed contains any users and the existing configuration is empty
          If($ldexceptionusers){
            Write-Message -Level "CHANGED" -Message "No existing exception users found. Updating lockdown mode exception user list on Host: $($vmhostv.name)."
            $lockdown.UpdateLockdownExceptions($ldexceptionusers)
            $changedcount++
          }
          # Pass if no configured exception users and none are in the approved list
          Else{
            Write-Message -Level "PASS" -Message "No exception users configured on Host: $($vmhostv.name)."
            $unchangedcount++
          }
        }
      }
    }
    Else{
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually when reverting to the default to avoid impacts to a VCF deployment where exception users may exist for service accounts."
      $skipcount++
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

# VCFE-9X-000206 SSH Ciphers
Try{
	$STIGID = "VCFE-9X-000206"
	$Title = "The ESX host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers."
  If($rulesenabled.VCFE9X000206){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshCiphers.Keys
      $value = [string]$stigsettings.sshCiphers.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshCiphers.Keys
      $value = [string]$defaultsettings.sshCiphers.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000207 SSH Gateway Ports
Try{
	$STIGID = "VCFE-9X-000207"
	$Title = "The ESX host Secure Shell (SSH) daemon must be configured to not allow gateway ports."
  If($rulesenabled.VCFE9X000207){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshGatewayports.Keys
      $value = [string]$stigsettings.sshGatewayports.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshGatewayports.Keys
      $value = [string]$defaultsettings.sshGatewayports.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000208 SSH PermitUserEnvironment
Try{
	$STIGID = "VCFE-9X-000208"
	$Title = "The ESX host Secure Shell (SSH) daemon must not permit user environment settings."
  If($rulesenabled.VCFE9X000208){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshPermituserenv.Keys
      $value = [string]$stigsettings.sshPermituserenv.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshPermituserenv.Keys
      $value = [string]$defaultsettings.sshPermituserenv.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000209 SSH PermitTunnel
Try{
	$STIGID = "VCFE-9X-000209"
	$Title = "The ESX host Secure Shell (SSH) daemon must not permit tunnels."
  If($rulesenabled.VCFE9X000209){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshPermittunnel.Keys
      $value = [string]$stigsettings.sshPermittunnel.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshPermittunnel.Keys
      $value = [string]$defaultsettings.sshPermittunnel.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000210 SSH ClientAliveCountMax
Try{
	$STIGID = "VCFE-9X-000210"
	$Title = "The ESX host Secure Shell (SSH) daemon must set a timeout count on idle sessions."
  If($rulesenabled.VCFE9X000210){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshClientalivecountmax.Keys
      $value = [string]$stigsettings.sshClientalivecountmax.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshClientalivecountmax.Keys
      $value = [string]$defaultsettings.sshClientalivecountmax.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000211 SSH ClientAliveInterval
Try{
	$STIGID = "VCFE-9X-000211"
	$Title = "The ESX host Secure Shell (SSH) daemon must set a timeout interval on idle sessions."
  If($rulesenabled.VCFE9X000211){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshClientaliveinterval.Keys
      $value = [string]$stigsettings.sshClientaliveinterval.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshClientaliveinterval.Keys
      $value = [string]$defaultsettings.sshClientaliveinterval.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000212 SSH AllowTCPForwarding
Try{
	$STIGID = "VCFE-9X-000212"
	$Title = "The ESX host Secure Shell (SSH) daemon must disable port forwarding."
  If($rulesenabled.VCFE9X000212){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshAllowtcpforwarding.Keys
      $value = [string]$stigsettings.sshAllowtcpforwarding.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshAllowtcpforwarding.Keys
      $value = [string]$defaultsettings.sshAllowtcpforwarding.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000213 SSH IgnoreRhosts
Try{
	$STIGID = "VCFE-9X-000213"
	$Title = "The ESX host Secure Shell (SSH) daemon must ignore .rhosts files."
  If($rulesenabled.VCFE9X000213){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshIgnorerhosts.Keys
      $value = [string]$stigsettings.sshIgnorerhosts.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshIgnorerhosts.Keys
      $value = [string]$defaultsettings.sshIgnorerhosts.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000214 SSH HostBasedAuthentication
Try{
	$STIGID = "VCFE-9X-000214"
	$Title = "The ESX host Secure Shell (SSH) daemon must not allow host-based authentication."
  If($rulesenabled.VCFE9X000214){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = [string]$stigsettings.sshHostbasedauth.Keys
      $value = [string]$stigsettings.sshHostbasedauth.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
          $changedcount++
        }
      }
    }
    Else{
      $name = [string]$defaultsettings.sshHostbasedauth.Keys
      $value = [string]$defaultsettings.sshHostbasedauth.Values
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
        If($results -eq $value){
          Write-Message -Level "PASS" -Message "SSHD setting: $name set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring SSHD setting: $name to $value on host: $($vmhost.name)."
          $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
          $sshsargs.keyword = $name
          $sshsargs.value = $value
          $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
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

# VCFE-9X-000215 Disable SNMP v1/v2
Try{
	$STIGID = "VCFE-9X-000215"
	$Title = "The ESX host must disable Simple Network Management Protocol (SNMP) v1 and v2c."
  If($rulesenabled.VCFE9X000215){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      # Get/Set-VMhostSnmp only works when connected directly to an ESX host.
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000216 Default Firewall Policy
Try{
	$STIGID = "VCFE-9X-000216"
	$Title = "The ESX host must configure the firewall to block network traffic by default."
  If($rulesenabled.VCFE9X000216){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.network.firewall.get.invoke()
        If($results.DefaultAction -ne "DROP" -or  $results.Enabled -ne "true"){
          Write-Message -Level "CHANGED" -Message "Default firewall policy not configured correctly on Host: $($vmhost.name). Disabling inbound/outbound traffic by default."
          $fwargs = $esxcli.network.firewall.set.CreateArgs()
          $fwargs.enabled = $stigsettings.firewallDefaultEnable
          $fwargs.defaultaction = $stigsettings.firewallDefaultAction
          $esxcli.network.firewall.set.Invoke($fwargs)
          $changedcount++
        }Else{
          Write-Message -Level "PASS" -Message "Default firewall policy configured correctly on Host: $($vmhost.name)."
          $unchangedcount++
        }
      }
    }
    Else{
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.network.firewall.get.invoke()
        If($results.DefaultAction -ne "DROP" -or  $results.Enabled -ne "true"){
          Write-Message -Level "CHANGED" -Message "Default firewall policy not configured correctly on Host: $($vmhost.name). Disabling inbound/outbound traffic by default."
          $fwargs = $esxcli.network.firewall.set.CreateArgs()
          $fwargs.enabled = $defaultsettings.firewallDefaultEnable
          $fwargs.defaultaction = $defaulsettings.firewallDefaultAction
          $esxcli.network.firewall.set.Invoke($fwargs)
          $changedcount++
        }Else{
          Write-Message -Level "PASS" -Message "Default firewall policy configured correctly on Host: $($vmhost.name)."
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

# VCFE-9X-000217 Firewall Rules
Try{
	$STIGID = "VCFE-9X-000217"
	$Title = "The ESX host must configure the firewall to restrict access to services running on the host."
  If($rulesenabled.VCFE9X000217){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $allowedIPs = $envstigsettings.allowedips
      ForEach($vmhost in $vmhosts){
        $fwsys = Get-View $vmhost.ExtensionData.ConfigManager.FirewallSystem
        # Get a list of all enabled firewall rules that are user configurable that allow all IP addresses
        $fwservices = $fwsys.FirewallInfo.Ruleset | Where-Object {($_.IpListUserConfigurable -eq $true) -and ($_.Enabled -eq $true) -and ($_.AllowedHosts.AllIp -eq $true) } | Sort-Object Key
        If(-not $fwservices){
          Write-Message -Level "PASS" -Message "No user configurable services with AllowAllIPs found on Host: $($vmhost.name)."
          $unchangedcount++
        }
        Else{
          # Populate new allowed IP networks object
          $newIpNetworks = @()
          ForEach($allowedIpNetwork in $allowedIPs){
            $allowedNetwork,$allowedNetworkPrefix = $allowedIpNetwork.split('/')
            $tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
            $tmp.network = $allowedNetwork
            $tmp.prefixLength = $allowedNetworkPrefix
            $newIpNetworks+=$tmp
          }
          # Loop through each firewall service that is user configurable, enabled, and currently set to allow all IPs
          ForEach($fwservice in $fwservices){
            Write-Message -Level "CHANGED" -Message "Configuring ESX firewall policy on service $($fwservice.Label) to $allowedIPs) on Host: $($vmhost.name)."
            If($fwservice.Key -eq "hyperbus"){
              # Add 169.254.0.0/16 range to hyperbus service if NSX is in use for internal communication
              $nsxIpNetworks = $newIpNetworks
              $tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
              $tmp.network = "169.254.0.0"
              $tmp.prefixLength = "16"
              $nsxIpNetworks+=$tmp
              # Create new object for rule IP list and disable allow all IPs
              $rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
              $rulesetIpListSpec.allIp = $false
              $rulesetIpListSpec.ipNetwork = $nsxIpNetworks
              # Create new object for update firewall rules with new IP ranges
              $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
              $rulesetSpec.allowedHosts = $rulesetIpListSpec
              $fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
              $changedcount++
            }
            ElseIf($fwservice.Key -eq "dhcp"){
              # Create new object for rule IP list and disable allow all IPs
              $rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
              $rulesetIpListSpec.allIp = $false
              $rulesetIpListSpec.ipAddress = "255.255.255.255"
              $rulesetIpListSpec.ipNetwork = $newIpNetworks
              # Create new object for update firewall rules with new IP ranges
              $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
              $rulesetSpec.allowedHosts = $rulesetIpListSpec
              $fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
              $changedcount++              
            }
            Else{
              # Create new object for rule IP list and disable allow all IPs
              $rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
              $rulesetIpListSpec.allIp = $false
              $rulesetIpListSpec.ipNetwork = $newIpNetworks
              # Create new object for update firewall rules with new IP ranges
              $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
              $rulesetSpec.allowedHosts = $rulesetIpListSpec
              $fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
              $changedcount++
            }
          }
        }
      }
    }
    Else{
      ForEach($vmhost in $vmhosts){
        $fwsys = Get-View $vmhost.ExtensionData.ConfigManager.FirewallSystem
        # Get a list of all enabled firewall rules that are user configurable that do NOT allow all IP addresses
        $fwservices = $fwsys.FirewallInfo.Ruleset | Where-Object {($_.IpListUserConfigurable -eq $true) -and ($_.Enabled -eq $true) -and ($_.AllowedHosts.AllIp -eq $false) } | Sort-Object Key
        If(-not $fwservices){
          Write-Message -Level "PASS" -Message "No user configurable services with AllowAllIPs disabled found on Host: $($vmhost.name)."
          $unchangedcount++
        }
        Else{
          # Loop through each firewall service that is user configurable, enabled, and currently set to NOT allow all IPs
          ForEach($fwservice in $fwservices){
            Write-Message -Level "CHANGED" -Message "Configuring ESX Firewall Policy on service $($fwservice.Label) to Allow All IPs on Host: $($vmhost.name)."
            # Create new object for rule IP list and disable allow all IPs
            $rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
            $rulesetIpListSpec.allIp = $true
            # Create new object for update firewall rules with new IP ranges
            $rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
            $rulesetSpec.allowedHosts = $rulesetIpListSpec
            $fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
            $changedcount++
          }
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

# VCFE-9X-000218 BlockGuestBPDU
Try{
	$STIGID = "VCFE-9X-000218"
	$Title = "The ESX host must enable Bridge Protocol Data Units (BPDU) filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
  If($rulesenabled.VCFE9X000218){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.blockGuestBpdu.Keys
        $value = [string]$stigsettings.blockGuestBpdu.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.blockGuestBpdu.Keys
        $value = [string]$defaultsettings.blockGuestBpdu.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000219 vSwitch Forged Transmits
Try{
	$STIGID = "VCFE-9X-000219"
	$Title = "The ESX host must configure virtual switch security policies to reject forged transmits."
  If($rulesenabled.VCFE9X000219){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $forgedtransmits = $stigsettings.forgedTransmits
      $forgedtransmitsinherit = $stigsettings.forgedTransmitsInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -ne $forgedtransmits){
              Write-Message -Level "CHANGED" -Message "Disabling forged transmits on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -ForgedTransmits $forgedtransmits -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Forged transmits disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -ne $forgedtransmits -xor $secpol.ForgedTransmitsInherited -eq $forgedtransmitsinherit){
              Write-Message -Level "CHANGED" -Message "Disabling forged transmits on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $forgedtransmitsinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Forged transmits disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
    Else{
      $forgedtransmits = $defaultsettings.forgedTransmits
      $forgedtransmitsinherit = $defaultsettings.forgedTransmitsInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -ne $forgedtransmits){
              Write-Message -Level "CHANGED" -Message "Disabling forged transmits on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -ForgedTransmits $forgedtransmits -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Forged transmits disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -ne $forgedtransmits -xor $secpol.ForgedTransmitsInherited -eq $forgedtransmitsinherit){
              Write-Message -Level "CHANGED" -Message "Disabling forged transmits on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $forgedtransmitsinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Forged transmits disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VCFE-9X-000220 vSwitch MAC Changes
Try{
	$STIGID = "VCFE-9X-000220"
	$Title = "The ESX host must configure virtual switch security policies to reject Media Access Control (MAC) address changes."
  If($rulesenabled.VCFE9X000220){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $macchanges = $stigsettings.macChanges
      $macchangesinherit = $stigsettings.macChangesInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -ne $macchanges){
              Write-Message -Level "CHANGED" -Message "Disabling MAC changes on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -MacChanges $macchanges -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "MAC changes disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -ne $macchanges -xor $secpol.MacChangesInherited -eq $macchangesinherit){
              Write-Message -Level "CHANGED" -Message "Disabling MAC changes on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -MacChangesInherited $macchangesinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "MAC changes disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
    Else{
      $macchanges = $defaultsettings.macChanges
      $macchangesinherit = $defaultsettings.macChangesInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -ne $macchanges){
              Write-Message -Level "CHANGED" -Message "Disabling MAC changes on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -MacChanges $macchanges -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "MAC changes disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -ne $macchanges -xor $secpol.MacChangesInherited -eq $macchangesinherit){
              Write-Message -Level "CHANGED" -Message "Disabling MAC changes on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -MacChangesInherited $macchangesinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "MAC changes disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VCFE-9X-000221 vSwitch Promiscious Mode
Try{
	$STIGID = "VCFE-9X-000221"
	$Title = "The ESX host must configure virtual switch security policies to reject promiscuous mode requests."
  If($rulesenabled.VCFE9X000221){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $promisciousmode = $stigsettings.promisciousMode
      $promisciousmodeinherit = $stigsettings.promisciousModeInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -ne $promisciousmode){
              Write-Message -Level "CHANGED" -Message "Disabling promiscious mode on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -AllowPromiscuous $promisciousmode -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Promiscious mode disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -ne $promisciousmode -xor $secpol.AllowPromiscuousInherited -eq $promisciousmodeinherit){
              Write-Message -Level "CHANGED" -Message "Disabling promiscious mode on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $promisciousmodeinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Promiscious mode disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
    Else{
      $promisciousmode = $defaultsettings.promisciousMode
      $promisciousmodeinherit = $defaultsettings.promisciousModeInherit
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -ne $promisciousmode){
              Write-Message -Level "CHANGED" -Message "Disabling promiscious mode on switch: $($sw.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -AllowPromiscuous $promisciousmode -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Promiscious mode disabled on switch: $($sw.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
          ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -ne $promisciousmode -xor $secpol.AllowPromiscuousInherited -eq $promisciousmodeinherit){
              Write-Message -Level "CHANGED" -Message "Disabling promiscious mode on portgroup: $($pg.name) on Host: $($vmhost.name)."
              $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $promisciousmodeinherit -Confirm:$false -ErrorAction Stop
              $changedcount++
            }Else{
              Write-Message -Level "PASS" -Message "Promiscious mode disabled portgroup: $($pg.name) on Host: $($vmhost.name)."
              $unchangedcount++
            }
          }
        }      
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VCFE-9X-000222 Net.DVFilterBindIpAddress
Try{
	$STIGID = "VCFE-9X-000222"
	$Title = "The ESX host must restrict use of the dvFilter network application programming interface (API)."
  If($rulesenabled.VCFE9X000222){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.dvFilterBindIpAddress.Keys
        $value = [string]$stigsettings.dvFilterBindIpAddress.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.dvFilterBindIpAddress.Keys
        $value = [string]$defaultsettings.dvFilterBindIpAddress.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VLAN Trunk
# VCFE-9X-000223 Standard Switch VGT
Try{
	$STIGID = "VCFE-9X-000223"
	$Title = "The ESX host must restrict the use of Virtual Guest Tagging (VGT) on standard switches."
  If($rulesenabled.VCFE9X000223){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
        If($switches.count -eq 0){
          Write-Message -Level "PASS" -Message "No Standard Switches exist on Host: $($vmhost.name) to check for trunked port groups."
          $unchangedcount++
        }Else{
          $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -eq "4095"}
          If($portgroups.count -eq 0){
            Write-Message -Level "PASS" -Message "No standard port groups found with trunked VLANs on Host: $($vmhost.name)."
            $unchangedcount++
          }Else{
            ForEach($pg in $portgroups){
              Write-Message -Level "ERROR" -Message "Portgroup: $($pg.name) found with VLAN ID set to 4095 on Host: $($vmhost.name).  Investigate and change or document waiver."
              $failedcount++
            }
          }
        }   
      }
    }
    Else{
      Write-Message -Level "SKIPPED" -Message "No action needed on this rule when ReverttoDefault is enabled."
      $skipcount++
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

# VCFE-9X-000224 UserVars.SuppressShellWarning
Try{
	$STIGID = "VCFE-9X-000224"
	$Title = "The ESX host must not suppress warnings that the local or remote shell sessions are enabled."
  If($rulesenabled.VCFE9X000224){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.suppressShellWarning.Keys
        $value = [string]$stigsettings.suppressShellWarning.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.suppressShellWarning.Keys
        $value = [string]$defaultsettings.suppressShellWarning.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000225 Mem.MemEagerZero
Try{
	$STIGID = "VCFE-9X-000225"
	$Title = "The ESX host must enable volatile key destruction."
  If($rulesenabled.VCFE9X000225){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.memEagerZero.Keys
        $value = [string]$stigsettings.memEagerZero.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.memEagerZero.Keys
        $value = [string]$defaultsettings.memEagerZero.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000226 Config.HostAgent.vmacore.soap.sessionTimeout
Try{
	$STIGID = "VCFE-9X-000226"
	$Title = "The ESX host must configure a session timeout for the vSphere API."
  If($rulesenabled.VCFE9X000226){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.apiTimeout.Keys
        $value = [string]$stigsettings.apiTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.apiTimeout.Keys
        $value = [string]$defaultsettings.apiTimeout.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000227 UserVars.SuppressHyperthreadWarning
Try{
	$STIGID = "VCFE-9X-000227"
	$Title = "The ESX host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
  If($rulesenabled.VCFE9X000227){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.suppressHyperWarning.Keys
        $value = [string]$stigsettings.suppressHyperWarning.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.suppressHyperWarning.Keys
        $value = [string]$defaultsettings.suppressHyperWarning.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000228 VMkernel.Boot.execInstalledOnly
Try{
	$STIGID = "VCFE-9X-000228"
	$Title = "The ESX host must only run binaries from signed VIBs."
  If($rulesenabled.VCFE9X000228){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.execInstalledOnly.Keys
        $value = [string]$stigsettings.execInstalledOnly.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.execInstalledOnly.Keys
        $value = [string]$defaultsettings.execInstalledOnly.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000229 Require execInstalledOnly for config encryption
Try{
	$STIGID = "VCFE-9X-000229"
	$Title = 'The ESX host must enable "execInstalledOnly" enforcement for configuration encryption.'
  If($rulesenabled.VCFE9X000229){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.settings.encryption.get.invoke()
        If($results.RequireExecutablesOnlyFromInstalledVIBs -eq [String]$stigsettings.execInstallEnforcement){
          Write-Message -Level "PASS" -Message "execInstalledOnly enforcement for configuration encryption set correctly to $($results.RequireExecutablesOnlyFromInstalledVIBs) on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring execInstalledOnly enforcement for configuration encryption on Host: $($vmhost.name)."
          $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
          $sbarg.requireexecinstalledonly = $stigsettings.execInstallEnforcement
          $esxcli.system.settings.encryption.set.Invoke($sbarg)
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.settings.encryption.get.invoke()
        If($results.RequireExecutablesOnlyFromInstalledVIBs -eq [String]$defaultsettings.execInstallEnforcement){
          Write-Message -Level "PASS" -Message "execInstalledOnly enforcement for configuration encryption set correctly to $($results.RequireExecutablesOnlyFromInstalledVIBs) on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring execInstalledOnly enforcement for configuration encryption on Host: $($vmhost.name)."
          $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
          $sbarg.requireexecinstalledonly = $defaultsettings.execInstallEnforcement
          $esxcli.system.settings.encryption.set.Invoke($sbarg)
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

# VCFE-9X-000230 Syslog.global.certificate.strictX509Compliance
Try{
	$STIGID = "VCFE-9X-000230"
	$Title = "The ESX host must enable strict x509 verification for SSL syslog endpoints."
  If($rulesenabled.VCFE9X000230){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.syslogCertStrict.Keys
        $value = [string]$stigsettings.syslogCertStrict.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.syslogCertStrict.Keys
        $value = [string]$defaultsettings.syslogCertStrict.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000231 Syslog.global.auditRecord.storageEnable
Try{
	$STIGID = "VCFE-9X-000231"
	$Title = "The ESX host must enable audit logging."
  If($rulesenabled.VCFE9X000231){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.syslogAuditEnable.Keys
        $value = [string]$stigsettings.syslogAuditEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.syslogAuditEnable.Keys
        $value = [string]$defaultsettings.syslogAuditEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000232 /etc/vmware/settings
Try{
	$STIGID = "VCFE-9X-000232"
	$Title = "The ESX host must not be configured to override virtual machine (VM) configurations."
  If($rulesenabled.VCFE9X000232){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000233 /etc/vmware/config
Try{
	$STIGID = "VCFE-9X-000233"
	$Title = "The ESX host must not be configured to override virtual machine (VM) logger settings."
  If($rulesenabled.VCFE9X000233){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
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

# VCFE-9X-000234 Entropy
Try{
	$STIGID = "VCFE-9X-000234"
	$Title = "The ESX host must use sufficient entropy for cryptographic operations."
  If($rulesenabled.VCFE9X000234){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $disableHwrng = $stigsettings.disableHwrng
      $entropySources = $stigsettings.entropySources
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        # hwrng
        $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
        If($results -eq $disableHwrng){
          Write-Message -Level "PASS" -Message "Entropy setting disableHwrng set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring entropy setting disableHwrng on Host: $($vmhost.name)."
          $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
          $enthwargs.setting = "disableHwrng"
          $enthwargs.value = $disableHwrng
          $esxcli.system.settings.kernel.set.invoke($enthwargs)
          $changedcount++
        }
        # sources
        $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "entropySources"} | Select-Object -ExpandProperty Configured
        If($results -eq $entropySources){
          Write-Message -Level "PASS" -Message "Entropy setting entropySources set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring entropy setting entropySources on Host: $($vmhost.name)."
          $entsrcargs = $esxcli.system.settings.kernel.set.CreateArgs()
          $entsrcargs.setting = "entropySources"
          $entsrcargs.value = $entropySources
          $esxcli.system.settings.kernel.set.invoke($entsrcargs)
          $changedcount++
        }
      }
    }
    Else{
      $disableHwrng = $defaultsettings.disableHwrng
      $entropySources = $defaultsettings.entropySources
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        # hwrng
        $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
        If($results -eq $disableHwrng){
          Write-Message -Level "PASS" -Message "Entropy setting disableHwrng set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring entropy setting disableHwrng on Host: $($vmhost.name)."
          $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
          $enthwargs.setting = "disableHwrng"
          $enthwargs.value = $disableHwrng
          $esxcli.system.settings.kernel.set.invoke($enthwargs)
          $changedcount++
        }
        # sources
        $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "entropySources"} | Select-Object -ExpandProperty Configured
        If($results -eq $entropySources){
          Write-Message -Level "PASS" -Message "Entropy setting entropySources set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Configuring entropy setting entropySources on Host: $($vmhost.name)."
          $entsrcargs = $esxcli.system.settings.kernel.set.CreateArgs()
          $entsrcargs.setting = "entropySources"
          $entsrcargs.value = $entropySources
          $esxcli.system.settings.kernel.set.invoke($entsrcargs)
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

# VCFE-9X-000235 Log Filtering
Try{
	$STIGID = "VCFE-9X-000235"
	$Title = "The ESX host must not enable log filtering."
  If($rulesenabled.VCFE9X000235){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $logfilteringenabled = $stigsettings.logFilteringEnabled
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
        If($results -eq $logfilteringenabled){
          Write-Message -Level "PASS" -Message "Log filtering set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Disabling log filtering on Host: $($vmhost.name)."
          $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
          $lfargs.logfilteringenabled = $logfilteringenabled
          $esxcli.system.syslog.config.logfilter.set.invoke($lfargs)
          $changedcount++
        }
      }
    }
    Else{
      $logfilteringenabled = $defaultsettings.logFilteringEnabled
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
        If($results -eq $logfilteringenabled){
          Write-Message -Level "PASS" -Message "Log filtering set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Disabling log filtering on Host: $($vmhost.name)."
          $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
          $lfargs.logfilteringenabled = $logfilteringenabled
          $esxcli.system.syslog.config.logfilter.set.invoke($lfargs)
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

# VCFE-9X-000236 Key Persistence
Try{
	$STIGID = "VCFE-9X-000236"
	$Title = "The ESX host must disable key persistence."
  If($rulesenabled.VCFE9X000236){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $disablekeypersistence = $stigsettings.disableKeyPersistence
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
        If($results -eq $false){
          Write-Message -Level "PASS" -Message "Key persistence set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Disabling key persistence on Host: $($vmhost.name)."
          $kpargs = $esxcli.system.security.keypersistence.disable.CreateArgs()
          $kpargs.removeallstoredkeys = $disablekeypersistence
          $esxcli.system.security.keypersistence.disable.invoke($kpargs)
          $changedcount++
        }
      }
    }
    Else{
      $disablekeypersistence = $defaultsettings.disableKeyPersistence
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
        If($results -eq $false){
          Write-Message -Level "PASS" -Message "Key persistence set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Disabling key persistence on Host: $($vmhost.name)."
          $kpargs = $esxcli.system.security.keypersistence.disable.CreateArgs()
          $kpargs.removeallstoredkeys = $disablekeypersistence
          $esxcli.system.security.keypersistence.disable.invoke($kpargs)
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

# VCFE-9X-000237 DCUI Shell Access
Try{
	$STIGID = "VCFE-9X-000237"
	$Title = "The ESX host must deny shell access for the dcui account."
  If($rulesenabled.VCFE9X000237){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $dcuishellaccess = $stigsettings.dcuiShellAccess
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess
        If($results -eq $false){
          Write-Message -Level "PASS" -Message "DCUI shell access set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Disabling DCUI shell access on Host: $($vmhost.name)."
          $dcuisaargs = $esxcli.system.account.set.CreateArgs()
          $dcuisaargs.id = "dcui"
          $dcuisaargs.shellaccess = $dcuishellaccess
          $esxcli.system.account.set.invoke($dcuisaargs)
          $changedcount++
        }
      }
    }
    Else{
      $dcuishellaccess = $defaultsettings.dcuiShellAccess
      ForEach($vmhost in $vmhosts){
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        $results = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess
        If($results -eq $true){
          Write-Message -Level "PASS" -Message "DCUI shell access set correctly to $results on Host: $($vmhost.name)."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Enabling DCUI shell access on Host: $($vmhost.name)."
          $dcuisaargs = $esxcli.system.account.set.CreateArgs()
          $dcuisaargs.id = "dcui"
          $dcuisaargs.shellaccess = $dcuishellaccess
          $esxcli.system.account.set.invoke($dcuisaargs)
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

# VCFE-9X-000238 Net.BMCNetworkEnable
Try{
	$STIGID = "VCFE-9X-000238"
	$Title = "The ESX host must disable virtual hardware management network interfaces."
  If($rulesenabled.VCFE9X000238){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.bmcNetworkEnable.Keys
        $value = [string]$stigsettings.bmcNetworkEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.bmcNetworkEnable.Keys
        $value = [string]$defaultsettings.bmcNetworkEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000239 Config.HostAgent.plugins.hostsvc.esxAdminsGroup
Try{
	$STIGID = "VCFE-9X-000239"
	$Title = "The ESX host must not use the default Active Directory ESX Admin group."
  If($rulesenabled.VCFE9X000239){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $domainstatus = Get-VMHost -Name $vmhost | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus
        If($domainstatus){
          $name = $envstigsettings.esxAdminsGroup.Keys
          $value = [string]$envstigsettings.esxAdminsGroup.Values
          ## Checking to see if current setting exists
          If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
            If($asetting.value -eq $value){
              Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
              $unchangedcount++
            }
            Else{
              Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
              $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
              $changedcount++
            }
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
            $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          $name = $stigsettings.esxAdminsGroup.Keys
          $value = [string]$stigsettings.esxAdminsGroup.Values
          ## Checking to see if current setting exists
          If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
            If($asetting.value -eq $value){
              Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
              $unchangedcount++
            }
            Else{
              Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
              $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
              $changedcount++
            }
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
            $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }          
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.esxAdminsGroup.Keys
        $value = [string]$defaultsettings.esxAdminsGroup.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000240 Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd
Try{
	$STIGID = "VCFE-9X-000240"
	$Title = "The ESX host must not automatically grant administrative permissions to Active Directory groups."
  If($rulesenabled.VCFE9X000240){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.esxAdminsGroupAutoAdd.Keys
        $value = [System.Convert]::ToBoolean([String]$stigsettings.esxAdminsGroupAutoAdd.Values)
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.esxAdminsGroupAutoAdd.Keys
        $value = [System.Convert]::ToBoolean([String]$defaultsettings.esxAdminsGroupAutoAdd.Values)
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000241 Config.HostAgent.plugins.vimsvc.authValidateInterval
Try{
	$STIGID = "VCFE-9X-000241"
	$Title = "The ESX host must not disable validation of users and groups."
  If($rulesenabled.VCFE9X000241){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.authValidateInterval.Keys
        $value = [string]$stigsettings.authValidateInterval.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.authValidateInterval.Keys
        $value = [string]$defaultsettings.authValidateInterval.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# VCFE-9X-000198 Syslog.global.auditRecord.storageEnable
Try{
	$STIGID = "VCFE-9X-000198"
	$Title = "The ESX host must enable audit logging."
  If($rulesenabled.VCFE9X000198){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.syslogAuditEnable.Keys
        $value = [string]$stigsettings.syslogAuditEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }
    }
    Else {
      ForEach($vmhost in $vmhosts){
        $name = $defaultsettings.syslogAuditEnable.Keys
        $value = [string]$defaultsettings.syslogAuditEnable.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on Host: $($vmhost.name)."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on Host: $($vmhost.name). Configuring value to $value."
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name does not exist on Host: $($vmhost.name). Creating setting and configuring value to $value."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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

# Lockdown Mode should be the last task in the script
# Lockdown Mode
Try{
	$STIGID = "VCFE-9X-000008"
	$Title = "The ESX host must enable lockdown mode."
  If($rulesenabled.VCFE9X000008){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      ForEach($vmhostv in $vmhostsv){
        If($vmhostv.config.LockdownMode -ne $stigsettings.lockdownlevel){
          Write-Message -Level "CHANGED" -Message "Enabling Lockdown mode with level: $($stigsettings.lockdownlevel) on Host: $($vmhostv.name)."
          $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
          $lockdown.ChangeLockdownMode($stigsettings.lockdownlevel)
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Lockdown mode configured correctly to $($stigsettings.lockdownlevel) on Host: $($vmhostv.name)."
          $unchangedcount++
        }
      }
    }
    Else{
      ForEach($vmhostv in $vmhostsv){
        If($vmhostv.config.LockdownMode -ne $defaultsettings.lockdownlevel){
          Write-Message -Level "CHANGED" -Message "Enabling Lockdown mode with level: $($defaultsettings.lockdownlevel) on Host: $($vmhostv.name)."
          $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
          $lockdown.ChangeLockdownMode($defaultsettings.lockdownlevel)
          $changedcount++
        }
        Else{
          Write-Message -Level "PASS" -Message "Lockdown mode configured correctly to $($defaultsettings.lockdownlevel) on Host: $($vmhostv.name)."
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
  "hostname" = $hostname
  "cluster" = $cluster
  "vmhosts" = $vmhosts.Name
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
