<# 
  .SYNOPSIS 
    The VMware Cloud Foundation vSphere vCenter STIG remediation script remediates vCenter
    against the VMware Cloud Foundation vSphere vCenter STIG Readiness Guide Version 1 Release 1.
  .DESCRIPTION
    The VMware Cloud Foundation vSphere vCenter STIG remediation script remediates vCenter
    against the VMware Cloud Foundation vSphere vCenter STIG Readiness Guide Version 1 Release 1.

    It is designed to connect to a target vCenter and remediate the vCenter rules. Individual STIG
    rules can be enabled or disabled in the provided variables file in the $rulesenabled hash table.

    The script will output a Powershell transcript as well as a JSON report with a summary of
    actions performed to the provided report directory.

  .NOTES 
    File Name  : VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 
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
  If specified, this switch parameter will inform the script to instead of hardening the target vCenter Server, revert to the default out of the box settings.
  .PARAMETER GlobalVarsFile
  Global Variables file name. Must be in the same directory as the script.
  .PARAMETER RemediationVarsFile
  Remediation Variables file name. Must be in the same directory as the script.

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 -vccred $vccred

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks

  .EXAMPLE
  PS> .\VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks -RevertToDefault

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
  [string]$RemediationVarsFile = "VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1"
)

# Script Variables
$STIGVersion = "STIG Readiness Guide Version 1 Release 1"
$ReportNamePrefix = "VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation"
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

# Revert to default warning
Try{
  Write-Header -Title "VMware vSphere vCenter STIG Remediation" -STIGVersion $STIGVersion -name $vcenter
  If($RevertToDefault){
    Write-Message -Level "WARNING" -Message "Revert to default values option specified. Hardening will be removed and stored to the default values."
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run output script header."
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
  Write-Message -Level "INFO" -Message "Connecting to vCenter SSO: $vcenter"
  Connect-SsoAdminServer -Server $vcenter -Credential $vccred -SkipCertificateCheck -ErrorAction Stop | Out-Null
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
  Write-Message -Level "INFO" -Message "Gathering info on target vCenter: $vcenter"
  $dvs = Get-VDSwitch | Sort-Object Name
  $dvpg = Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq "standard" -and $_.IsUplink -eq $false} | Sort-Object Name
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to gather information on target vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message $_.Exception
  Write-Message -Level "INFO" -Message "Disconnecting from vCenter Server: $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Write-Message -Level "INFO" -Message "Disconnecting from vCenter SSO: $vcenter"
  Disconnect-SsoAdminServer -Server $vcenter
  Exit -1
}

# VCFA-9X-000017 SSO Max Failed Attempts/Interval
Try{
	$STIGID = "VCFA-9X-000004"
	$Title = "The VMware Cloud Foundation vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period."
  If($rulesenabled.VCFA9X000017){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Get-SsoLockoutPolicy -OutVariable ssolockpolicies | Out-Null
      If($ssolockpolicies.MaxFailedAttempts -ne $stigsettings.ssoMaxFailedAttempts -or
         $ssolockpolicies.FailedAttemptIntervalSec -ne $stigsettings.ssoFailedAttemptIntSec){
        Write-Message -Level "CHANGED" -Message "SSO lockout policy updated to MaxFailedAttempts: $($ssolockpolicies.MaxFailedAttempts) and FailedAttemptIntervalSec: $($ssolockpolicies.FailedAttemptIntervalSec) on vCenter: $vcenter."
        $ssolockpolicies | Set-SsoLockoutPolicy -MaxFailedAttempts $stigsettings.ssoMaxFailedAttempts -FailedAttemptIntervalSec $stigsettings.ssoFailedAttemptIntSec | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO lockout policy set correctly to MaxFailedAttempts: $($stigsettings.ssoMaxFailedAttempts) and FailedAttemptIntervalSec: $($stigsettings.ssoFailedAttemptIntSec) on vCenter: $vcenter."
        $unchangedcount++
      }
    }
    Else{
      Get-SsoLockoutPolicy -OutVariable ssolockpolicies | Out-Null
      If($ssolockpolicies.MaxFailedAttempts -ne $defaultsettings.ssoMaxFailedAttempts -or
         $ssolockpolicies.FailedAttemptIntervalSec -ne $defaultsettings.ssoFailedAttemptIntSec){
        Write-Message -Level "CHANGED" -Message "SSO lockout policy updated to MaxFailedAttempts: $($ssolockpolicies.MaxFailedAttempts) and FailedAttemptIntervalSec: $($ssolockpolicies.FailedAttemptIntervalSec) on vCenter: $vcenter."
        $ssolockpolicies | Set-SsoLockoutPolicy -MaxFailedAttempts $defaultsettings.ssoMaxFailedAttempts -FailedAttemptIntervalSec $defaultsettings.ssoFailedAttemptIntSec | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO lockout policy set correctly to MaxFailedAttempts: $($defaultsettings.ssoMaxFailedAttempts) and FailedAttemptIntervalSec: $($defaultsettings.ssoFailedAttemptIntSec) on vCenter: $vcenter."
        $unchangedcount++
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

# VCFA-9X-000018 Login Banner
Try{
	$STIGID = "VCFA-9X-000018"
	$Title = "The VMware Cloud Foundation vCenter Server must display the Standard Mandatory DOD Notice and Consent Banner before logon."
  If($rulesenabled.VCFA9X000018){
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

# VCFA-9X-000028 Log Level
Try{
	$STIGID = "VCFA-9X-000028"
	$Title = "The VMware Cloud Foundation vCenter Server must produce audit records containing information to establish what type of events occurred."
  If($rulesenabled.VCFA9X000028){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = $stigsettings.configLogLevel.Keys
      $value = [string]$stigsettings.configLogLevel.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
    }
    Else {
      $name = $defaultsettings.configLogLevel.Keys
      $value = [string]$defaultsettings.configLogLevel.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
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

# VCFA-9X-000051 Verify Plugins
Try{
	$STIGID = "VCFA-9X-000051"
	$Title = "VMware Cloud Foundation vCenter Server client plugins must be verified."
  If($rulesenabled.VCFA9X000051){
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

# VCFA-9X-000063 SSO Password Policy
Try{
	$STIGID = "VCFA-9X-000063"
	$Title = "The VMware Cloud Foundation vCenter Server must enforce password complexity requirements."
  If($rulesenabled.VCFA9X000063){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Get-SsoPasswordPolicy -OutVariable ssopwpolicies | Out-Null
      If($ssopwpolicies.MinLength -ne $stigsettings.ssoPwPolicyMinLength -or 
         $ssopwpolicies.MaxLength -ne $stigsettings.ssoPwPolicyMaxLength -or 
         $ssopwpolicies.MinLowercaseCount -ne $stigsettings.ssoPwPolicyMinLower -or 
         $ssopwpolicies.MinUppercaseCount -ne $stigsettings.ssoPwPolicyMinUpper -or 
         $ssopwpolicies.MinNumericCount -ne $stigsettings.ssoPwPolicyMinNumeric -or 
         $ssopwpolicies.MinSpecialCharCount -ne $stigsettings.ssoPwPolicyMinSpecial){
        Write-Message -Level "CHANGED" -Message "SSO password policy set incorrectly on vCenter: $vcenter."
        $ssopwpolicies | Set-SsoPasswordPolicy -MinLength $stigsettings.ssoPwPolicyMinLength -MaxLength $stigsettings.ssoPwPolicyMaxLength -MinLowercaseCount $stigsettings.ssoPwPolicyMinLower -MinUppercaseCount $stigsettings.ssoPwPolicyMinUpper -MinNumericCount $stigsettings.ssoPwPolicyMinNumberic -MinSpecialCharCount $stigsettings.ssoPwPolicyMinSpecial | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO password policy set correctly on vCenter: $vcenter."
        $unchangedcount++
      }
    }
    Else {
      Get-SsoPasswordPolicy -OutVariable ssopwpolicies | Out-Null
      If($ssopwpolicies.MinLength -ne $defaultsettings.ssoPwPolicyMinLength -or 
         $ssopwpolicies.MaxLength -ne $defaultsettings.ssoPwPolicyMaxLength -or 
         $ssopwpolicies.MinLowercaseCount -ne $defaultsettings.ssoPwPolicyMinLower -or 
         $ssopwpolicies.MinUppercaseCount -ne $defaultsettings.ssoPwPolicyMinUpper -or 
         $ssopwpolicies.MinNumericCount -ne $defaultsettings.ssoPwPolicyMinNumeric -or 
         $ssopwpolicies.MinSpecialCharCount -ne $defaultsettings.ssoPwPolicyMinSpecial){
        Write-Message -Level "CHANGED" -Message "SSO password policy set incorrectly on vCenter: $vcenter."
        $ssopwpolicies | Set-SsoPasswordPolicy -MinLength $defaultsettings.ssoPwPolicyMinLength -MaxLength $defaultsettings.ssoPwPolicyMaxLength -MinLowercaseCount $defaultsettings.ssoPwPolicyMinLower -MinUppercaseCount $defaultsettings.ssoPwPolicyMinUpper -MinNumericCount $defaultsettings.ssoPwPolicyMinNumberic -MinSpecialCharCount $defaultsettings.ssoPwPolicyMinSpecial | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO password policy set correctly on vCenter: $vcenter."
        $unchangedcount++
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

# VCFA-9X-000082 Session timeout
Try{
	$STIGID = "VCFA-9X-000082"
	$Title = "The VMware Cloud Foundation vCenter Server must terminate sessions after 15 minutes of inactivity."
  If($rulesenabled.VCFA9X000082){
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

# VCFA-9X-000090 Verify roles and permissions
Try{
	$STIGID = "VCFA-9X-000090"
	$Title = "VMware Cloud Foundation vCenter Server assigned roles and permissions must be verified."
  If($rulesenabled.VCFA9X000090){
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

# VCFA-9X-000105 Enable NIOC
Try{
	$STIGID = "VCFA-9X-000105"
	$Title = "The VMware Cloud Foundation vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC)."
  If($rulesenabled.VCFA9X000105){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.ExtensionData.Config.NetworkResourceManagementEnabled -ne $stigsettings.dvsEnableNIOC){
            Write-Message -Level "CHANGED" -Message "Enabling Network IO Control on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            ($switch | Get-View).EnableNetworkResourceManagement($stigsettings.dvsEnableNIOC)
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Network IO Control enabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.ExtensionData.Config.NetworkResourceManagementEnabled -ne $defaultsettings.dvsEnableNIOC){
            Write-Message -Level "CHANGED" -Message "Enabling Network IO Control on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            ($switch | Get-View).EnableNetworkResourceManagement($defaultsettings.dvsEnableNIOC)
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Network IO Control enabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
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

# VCFA-9X-000117 SSO Account Alarm
Try{
	$STIGID = "VCFA-9X-000117"
	$Title = "The VMware Cloud Foundation vCenter Server must notify system administrators (SAs) and the information system security officer (ISSO) when Single Sign-On (SSO) account actions occur."
  If($rulesenabled.VCFA9X000117){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $ssoalarm = Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"}
      If($ssoalarm){
        If($ssoalarm.Enabled -eq $false -and $ssoalarm.count -eq 1){
          Write-Message -Level "CHANGED" -Message "Enabling existing alarm for event ID: com.vmware.sso.PrincipalManagement with name: $($ssoalarm.name) on vCenter: $vcenter."
          $ssoalarm | Set-AlarmDefinition -Enabled $true | Out-Null
          $changedcount++
        }ElseIf($ssoalarm.Enabled -eq $true -and $ssoalarm.count -eq 1){
          Write-Message -Level "PASS" -Message "Found existing enabled alarm for event ID: com.vmware.sso.PrincipalManagement with name: $($ssoalarm.name) on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "SKIPPED" -Message "More than 1 alarm for event ID: com.vmware.sso.PrincipalManagement found. Manual verification required."
          $skipcount++
        }
      }
      Else{
        Write-Message -Level "CHANGED" -Message "No existing alarm found. Creating alarm for com.vmware.sso.PrincipalManagement on vCenter: $vcenter."
        $entity = New-Object VMware.Vim.ManagedObjectReference
        $entity.Type = 'Folder'
        $entity.Value = 'group-d1'
        $spec = New-Object VMware.Vim.AlarmSpec
        $spec.Expression = New-Object VMware.Vim.OrAlarmExpression
        $spec.Expression.Expression = New-Object VMware.Vim.AlarmExpression[] (1)
        $spec.Expression.Expression[0] = New-Object VMware.Vim.EventAlarmExpression
        $spec.Expression.Expression[0].EventTypeId = 'com.vmware.sso.PrincipalManagement'
        $spec.Expression.Expression[0].EventType = "Event"
        $spec.Expression.Expression[0].ObjectType = "Folder"
        $spec.Expression.Expression[0].Status = 'yellow'
        $spec.Name = 'SSO Account Action Alert'
        $spec.Description = 'Alert on any SSO account action and show warning in vCenter.'
        $spec.Enabled = $true
        $spec.Setting = New-Object VMware.Vim.AlarmSetting
        $spec.Setting.ToleranceRange = 0
        $spec.Setting.ReportingFrequency = 300
        $amview = Get-View -Id 'AlarmManager-AlarmManager'
        $amview.CreateAlarm($entity, $spec) | Out-Null
        $changedcount++
      }
    }
    Else {

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

# VCFA-9X-000139 SSO Disable auto unlock
Try{
	$STIGID = "VCFA-9X-000139"
	$Title = "The VMware Cloud Foundation vCenter Server must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded."
  If($rulesenabled.VCFA9X000139){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Get-SsoLockoutPolicy -OutVariable ssolockpolicies | Out-Null
      If($ssolockpolicies.AutoUnlockIntervalSec -ne $stigsettings.ssoAutoUnlockIntSec){
        Write-Message -Level "CHANGED" -Message "SSO lockout policy set updated to AutoUnlockIntervalSec: $($stigsettings.ssoAutoUnlockIntSec) on vCenter: $vcenter."
        $ssolockpolicies | Set-SsoLockoutPolicy -AutoUnlockIntervalSec $stigsettings.ssoAutoUnlockIntSec | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO lockout policy set correctly to AutoUnlockIntervalSec: $($stigsettings.ssoAutoUnlockIntSec) on vCenter: $vcenter."
        $unchangedcount++
      }
    }
    Else{
      Get-SsoLockoutPolicy -OutVariable ssolockpolicies | Out-Null
      If($ssolockpolicies.AutoUnlockIntervalSec -ne $defaultsettings.ssoAutoUnlockIntSec){
        Write-Message -Level "CHANGED" -Message "SSO lockout policy set updated to AutoUnlockIntervalSec: $($defaultsettings.ssoAutoUnlockIntSec) on vCenter: $vcenter."
        $ssolockpolicies | Set-SsoLockoutPolicy -AutoUnlockIntervalSec $defaultsettings.ssoAutoUnlockIntSec | Out-Null
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "SSO lockout policy set correctly to AutoUnlockIntervalSec: $($defaultsettings.ssoAutoUnlockIntSec) on vCenter: $vcenter."
        $unchangedcount++
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

# VCFA-9X-000153 NTP
Try{
	$STIGID = "VCFA-9X-000153"
	$Title = "The VMware Cloud Foundation vCenter Server must compare internal information system clocks with an authoritative time server."
  If($rulesenabled.VCFA9X000153){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $approvedNtpServers = $envstigsettings.ntpServers
      $currentntpservers = Invoke-GetNtp -Confirm:$false
      $timesyncstatus = Invoke-GetTimesync -Confirm:$false
      If($currentntpservers.count -eq "0"){
        Write-Message -Level "CHANGED" -Message "No NTP servers configured on vCenter: $vcenter. Configuring the vCenter with NTP servers: $approvedNtpServers."
        $NtpSetRequestBody = Initialize-ApplianceNtpSetrequest -Servers $approvedNtpServers
        Invoke-SetNtp -NtpSetRequestBody $NtpSetRequestBody -Confirm:$false | Out-Null
      }
      ElseIf(!(Compare-Object -ReferenceObject $approvedNtpServers -DifferenceObject $currentntpservers) -and
             $timesyncstatus -eq "NTP"){
        Write-Message -Level "PASS" -Message "NTP servers: $currentntpservers configured correctly on vCenter: $vcenter."
      }Else{
        Write-Message -Level "CHANGED" -Message "Configured NTP servers on vCenter: $vcenter do not match approved NTP servers or NTP is not enabled. Configuring the vCenter with NTP servers: $approvedNtpServers."
        $NtpSetRequestBody = Initialize-ApplianceNtpSetrequest -Servers $approvedNtpServers
        Invoke-SetNtp -NtpSetRequestBody $NtpSetRequestBody -Confirm:$false | Out-Null
      }
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "NTP configuration not updated during revert to default. Please review this manually if changes are needed."
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

# VCFA-9X-000191 vSAN DAR Encryption
Try{
	$STIGID = "VCFA-9X-000191"
	$Title = "The VMware Cloud Foundation vCenter Server must enable data at rest encryption for vSAN."
  If($rulesenabled.VCFA9X000191){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually. vSAN data at rest encryption should be enabled manually with an appropriate key provider."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "No action taken during revert action. vSAN data at rest encryption should be disabled manually if changes are needed."
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

# VCFA-9X-000252 VDS Health Check
Try{
	$STIGID = "VCFA-9X-000252"
	$Title = "The VMware Cloud Foundation vCenter Server must disable the distributed virtual switch health check."
  If($rulesenabled.VCFA9X000252){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.ExtensionData.Config.HealthCheckConfig.Enable[0] -eq $true -or $switch.ExtensionData.Config.HealthCheckConfig.Enable[1] -eq $true){
            Write-Message -Level "CHANGED" -Message "Disabling health checks on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            ($switch | Get-View).UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Health checks disabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.ExtensionData.Config.HealthCheckConfig.Enable[0] -eq $true -or $switch.ExtensionData.Config.HealthCheckConfig.Enable[1] -eq $true){
            Write-Message -Level "CHANGED" -Message "Disabling health checks on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            ($switch | Get-View).UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Health checks disabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
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

# VCFA-9X-000257 SNMP v3
Try{
	$STIGID = "VCFA-9X-000257"
	$Title = "The VMware Cloud Foundation vCenter Server must enforce SNMPv3 security features where SNMP is required."
  If($rulesenabled.VCFA9X000257){
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

# VCFA-9X-000270 Disable K/B and krbtgt users
Try{
	$STIGID = "VCFA-9X-000270"
	$Title = "The vCenter Server must disable accounts used for Integrated Windows Authentication (IWA)."
  If($rulesenabled.VCFA9X000270){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If((Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "krbtgt/VSPHERE.LOCAL").Disabled -eq $true){
        Write-Message -Level "PASS" -Message "User: krbtgt/VSPHERE.LOCAL is already disabled on vCenter: $vcenter."
        $unchangedcount++
      }Else{
        Write-Message -Level "CHANGED" -Message "Disabling user: krbtgt/VSPHERE.LOCAL on vCenter: $vcenter."
        Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "krbtgt/VSPHERE.LOCAL" | Set-SsoPersonUser -Enable $false | Out-Null
        $changedcount++
      }
      If((Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "K/M").Disabled -eq $true){
        Write-Message -Level "PASS" -Message "User: K/M is already disabled on vCenter: $vcenter."
        $unchangedcount++
      }Else{
        Write-Message -Level "CHANGED" -Message "Disabling user: K/M on vCenter: $vcenter."
        Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "K/M" | Set-SsoPersonUser -Enable $false | Out-Null
        $changedcount++
      }
    }
    Else {
      If((Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "krbtgt/VSPHERE.LOCAL").Disabled -eq $false){
        Write-Message -Level "PASS" -Message "User: krbtgt/VSPHERE.LOCAL is already enabled on vCenter: $vcenter."
        $unchangedcount++
      }Else{
        Write-Message -Level "CHANGED" -Message "Enabling user: krbtgt/VSPHERE.LOCAL on vCenter: $vcenter."
        Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "krbtgt/VSPHERE.LOCAL" | Set-SsoPersonUser -Enable $true | Out-Null
        $changedcount++
      }
      If((Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "K/M").Disabled -eq $false){
        Write-Message -Level "PASS" -Message "User: K/M is already enabled on vCenter: $vcenter."
        $unchangedcount++
      }Else{
        Write-Message -Level "CHANGED" -Message "Enabling user: K/M on vCenter: $vcenter."
        Get-SsoPersonUser -Domain $envstigsettings.ssoDomain -Name "K/M" | Set-SsoPersonUser -Enable $true | Out-Null
        $changedcount++
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

# VCFA-9X-000312 Trusted root certificates
Try{
	$STIGID = "VCFA-9X-000312"
	$Title = "The VMware Cloud Foundation vCenter Server must include only approved trust anchors in trust stores or certificate stores managed by the organization."
  If($rulesenabled.VCFA9X000312){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually. Validate trusted root certificates in vCenter."
      $skipcount++
    }
    Else {
      Write-Message -Level "SKIPPED" -Message "No remediation needed for revert to default action."
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

# VCFA-9X-000322 Disable SNMP v2
Try{
	$STIGID = "VCFA-9X-000322"
	$Title = "The VMware Cloud Foundation vCenter Server must disable SNMPv1/2 receivers."
  If($rulesenabled.VCFA9X000322){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $snmpview = Get-View -Id 'OptionManager-VpxSettings'
      $snmprecs = $snmpview.setting | Where-Object {$_.key -match 'snmp.receiver.*.enabled'}
      ForEach($snmprec in $snmprecs){
        If($snmprec.value -ne $false){
          Write-Message -Level "CHANGED" -Message "Disalbing SNMP v2 Receiver: $($snmprec.key) on vCenter: $vcenter."
          $updateValue = New-Object VMware.Vim.OptionValue[] (1)
          $updateValue[0] = New-Object VMware.Vim.OptionValue
          $updateValue[0].Value = $false
          $updateValue[0].Key = $snmprec.key
          $updatesnmp = Get-View -Id 'OptionManager-VpxSettings'
          $updatesnmp.UpdateOptions($updateValue)
          $changedcount++
        }Else{
          Write-Message -Level "PASS" -Message "SNMP v2 Receiver: $($snmprec.key) is disabled on vCenter: $vcenter."
          $unchangedcount++
        }
      }
    }
    Else {
      $snmpview = Get-View -Id 'OptionManager-VpxSettings'
      $snmprecs = $snmpview.setting | Where-Object {$_.key -match 'snmp.receiver.*.enabled'}
      ForEach($snmprec in $snmprecs){
        If($snmprec.key -eq "snmp.receiver.1.enabled" -and $snmprec.value -eq $false){
          Write-Message -Level "CHANGED" -Message "Enabling SNMP v2 Receiver: $($snmprec.key) on vCenter: $vcenter."
          $updateValue = New-Object VMware.Vim.OptionValue[] (1)
          $updateValue[0] = New-Object VMware.Vim.OptionValue
          $updateValue[0].Value = $true
          $updateValue[0].Key = $snmprec.key
          $updatesnmp = Get-View -Id 'OptionManager-VpxSettings'
          $updatesnmp.UpdateOptions($updateValue)
          $changedcount++
        }ElseIf($snmprec.key -eq "snmp.receiver.1.enabled" -and $snmprec.value -eq $true){
          Write-Message -Level "PASS" -Message "SNMP v2 Receiver: $($snmprec.key) is enabled on vCenter: $vcenter."
          $unchangedcount++
        }ElseIf($snmprec.key -ne "snmp.receiver.1.enabled" -and $snmprec.value -eq $true){
          Write-Message -Level "CHANGED" -Message "Disabling SNMP v2 Receiver: $($snmprec.key) on vCenter: $vcenter."
          $updateValue = New-Object VMware.Vim.OptionValue[] (1)
          $updateValue[0] = New-Object VMware.Vim.OptionValue
          $updateValue[0].Value = $false
          $updateValue[0].Key = $snmprec.key
          $updatesnmp = Get-View -Id 'OptionManager-VpxSettings'
          $updatesnmp.UpdateOptions($updateValue)
          $changedcount++
        }Else{
          Write-Message -Level "PASS" -Message "SNMP v2 Receiver: $($snmprec.key) is disabled on vCenter: $vcenter."
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

# VCFA-9X-000323 Distributed Port Group Forged Transmits
Try{
	$STIGID = "VCFA-9X-000323"
	$Title = "The VMware Cloud Foundation vCenter Server must set the distributed port group Forged Transmits policy to 'Reject'."
  If($rulesenabled.VCFA9X000323){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.ForgedTransmits -eq $stigsettings.forgedTransmits){
            $boolvalue = [System.Convert]::ToBoolean([String]$stigsettings.forgedTransmits)
            Write-Message -Level "CHANGED" -Message "Disabling Forged Transmits on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -ForgedTransmits $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Forged Transmits disabled on Port Group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.ForgedTransmits -eq $defaultsettings.forgedTransmits){
            $boolvalue = [System.Convert]::ToBoolean([String]$defaultsettings.forgedTransmits)
            Write-Message -Level "CHANGED" -Message "Disabling Forged Transmits on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -ForgedTransmits $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Forged Transmits disabled on Port Group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000324 Distributed Port Group MAC Changes
Try{
	$STIGID = "VCFA-9X-000324"
	$Title = "The VMware Cloud Foundation vCenter Server must set the distributed port group Media Access Control (MAC) Address Change policy to 'Reject'."
  If($rulesenabled.VCFA9X000324){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.MacChanges -eq $stigsettings.macChanges){
            $boolvalue = [System.Convert]::ToBoolean([String]$stigsettings.macChanges)
            Write-Message -Level "CHANGED" -Message "Disabling MAC Changes on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -MacChanges $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "MAC Changes disabled on Port Group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.MacChanges -eq $defaultsettings.macChanges){
            $boolvalue = [System.Convert]::ToBoolean([String]$defaultsettings.macChanges)
            Write-Message -Level "CHANGED" -Message "Disabling MAC Changes on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -MacChanges $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "MAC Changes disabled on Port Group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000325 Distributed Port Group Promiscuous Mode
Try{
	$STIGID = "VCFA-9X-000325"
	$Title = "The VMware Cloud Foundation vCenter Server must set the distributed port group Promiscuous Mode policy to 'Reject'."
  If($rulesenabled.VCFA9X000325){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.AllowPromiscuous -eq $stigsettings.promisciousMode){
            $boolvalue = [System.Convert]::ToBoolean([String]$stigsettings.promisciousMode)
            Write-Message -Level "CHANGED" -Message "Disabling Promiscuous Mode on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -AllowPromiscuous $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Promiscuous Mode disabled on Port Group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      }Else{
        ForEach($pg in $dvpg){
          $policy = $pg | Get-VDSecurityPolicy
          If($policy.AllowPromiscuous -eq $defaulsettings.promisciousMode){
            $boolvalue = [System.Convert]::ToBoolean([String]$defaultsettings.promisciousMode)
            Write-Message -Level "CHANGED" -Message "Disabling Promiscuous Mode on Port Group: $($pg.name) on vCenter: $vcenter."
            $policy | Set-VDSecurityPolicy -AllowPromiscuous $boolvalue
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Promiscuous Mode disabled on Port Group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000326 Netflow collector IP
Try{
	$STIGID = "VCFA-9X-000326"
	$Title = "The VMware Cloud Foundation vCenter Server must only send NetFlow traffic to authorized collectors."
  If($rulesenabled.VCFA9X000326){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($switch in $dvs){
          If(!([string]::IsNullOrEmpty($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress))){
            If($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress -ne $envstigsettings.netflowCollectorIp){
              Write-Message -Level "CHANGED" -Message "Unknown NetFlow collector: $($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress) found on switch: $($switch.name) on vCenter: $vcenter."
              Write-Message -Level "CHANGED" -Message "Updating NetFlow collector to $($envstigsettings.netflowCollectorIp) on switch: $($switch.name) on vCenter: $vcenter."
              $switchview = $switch | Get-View
              $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
              $spec.configversion = $switchview.Config.ConfigVersion
              $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
              $spec.IpfixConfig.CollectorIpAddress = $envstigsettings.vcNetflowCollectorIp
              $spec.IpfixConfig.CollectorPort = "0"
              $spec.IpfixConfig.ObservationDomainId = "0"
              $spec.IpfixConfig.ActiveFlowTimeout = "60"
              $spec.IpfixConfig.IdleFlowTimeout = "15"
              $spec.IpfixConfig.SamplingRate = "4096"
              $spec.IpfixConfig.InternalFlowsOnly = $False
              $switchview.ReconfigureDvs_Task($spec) | Out-Null
              $changedcount++
            }
            Else{
              Write-Message -Level "PASS" -Message "No unknown NetFlow collectors configured on switch: $($switch.name) on vCenter: $vcenter."
              $unchangedcount++
            }
          }
          Else{
            Write-Message -Level "PASS" -Message "No NetFlow collectors configured on switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++            
          }
        }
        If($envstigsettings.netflowDisableonallPortGroups){
          ForEach($pg in $dvpg){
            If($pg.ExtensionData.Config.DefaultPortConfig.IpfixEnabled.value -eq $true){
              Write-Message -Level "CHANGED" -Message "Disabling NetFlow collection on Port group: $($pg.name) on vCenter: $vcenter."
              $pgview = $pg | Get-View
              $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
              $spec.configversion = $pgview.Config.ConfigVersion
              $spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
              $spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
              $spec.defaultPortConfig.ipfixEnabled.inherited = $true
              $spec.defaultPortConfig.ipfixEnabled.value = $false
              $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
              $changedcount++
            }
            Else{
              Write-Message -Level "PASS" -Message "NetFlow collection disabled on Port group: $($pg.name) on vCenter: $vcenter."
              $unchangedcount++
            }
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($switch in $dvs){
          If(!([string]::IsNullOrEmpty($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress))){
            Write-Message -Level "CHANGED" -Message "Unknown NetFlow collector: $($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress) found on switch: $($switch.name) on vCenter: $vcenter."
            Write-Message -Level "CHANGED" -Message "Removing NetFlow collector on switch: $($switch.name) on vCenter: $vcenter."
            $switchview = $switch | Get-View
            $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
            $spec.configversion = $switchview.Config.ConfigVersion
            $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
            $spec.IpfixConfig.CollectorIpAddress = $envstigsettings.vcNetflowCollectorIp
            $spec.IpfixConfig.CollectorPort = "0"
            $spec.IpfixConfig.ObservationDomainId = "0"
            $spec.IpfixConfig.ActiveFlowTimeout = "60"
            $spec.IpfixConfig.IdleFlowTimeout = "15"
            $spec.IpfixConfig.SamplingRate = "4096"
            $spec.IpfixConfig.InternalFlowsOnly = $False
            $switchview.ReconfigureDvs_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "No NetFlow collectors configured on switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++            
          }
        }
        If($defaultsettings.netflowDisableonallPortGroups){
          ForEach($pg in $dvpg){
            If($pg.ExtensionData.Config.DefaultPortConfig.IpfixEnabled.value -eq $true){
              Write-Message -Level "CHANGED" -Message "Disabling NetFlow collection on Port group: $($pg.name) on vCenter: $vcenter."
              $pgview = $pg | Get-View
              $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
              $spec.configversion = $pgview.Config.ConfigVersion
              $spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
              $spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
              $spec.defaultPortConfig.ipfixEnabled.inherited = $true
              $spec.defaultPortConfig.ipfixEnabled.value = $false
              $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
              $changedcount++
            }
            Else{
              Write-Message -Level "PASS" -Message "NetFlow collection disabled on Port group: $($pg.name) on vCenter: $vcenter."
              $unchangedcount++
            }
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

# VCFA-9X-000327 VLAN Trunking
Try{
	$STIGID = "VCFA-9X-000327"
	$Title = "The VMware Cloud Foundation vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized."
  If($rulesenabled.VCFA9X000327){
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

# VCFA-9X-000328 VirtualCenter.VimPasswordExpirationInDays
Try{
	$STIGID = "VCFA-9X-000328"
	$Title = "The VMware Cloud Foundation vCenter Server must configure the 'vpxuser' auto-password to be changed every 30 days."
  If($rulesenabled.VCFA9X000328){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = $stigsettings.vimPasswordExpirationInDays.Keys
      $value = [string]$stigsettings.vimPasswordExpirationInDays.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
    }
    Else {
      $name = $defaultsettings.vimPasswordExpirationInDays.Keys
      $value = [string]$defaultsettings.vimPasswordExpirationInDays.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
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

# VCFA-9X-000329 vpxd.event.syslog.enabled
Try{
	$STIGID = "VCFA-9X-000329"
	$Title = "The VMware Cloud Foundation vCenter Server must be configured to send events to a central log server."
  If($rulesenabled.VCFA9X000329){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = $stigsettings.sendEventsSyslog.Keys
      $value = [string]$stigsettings.sendEventsSyslog.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
    }
    Else {
      $name = $defaultsettings.sendEventsSyslog.Keys
      $value = [string]$defaultsettings.sendEventsSyslog.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
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

# VCFA-9X-000330 vSAN Internet
Try{
	$STIGID = "VCFA-9X-000330"
	$Title = "The VMware Cloud Foundation vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List (HCL) by use of an external proxy server."
  If($rulesenabled.VCFA9X000330){
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

# VCFA-9X-000331 vSAN iSCSI CHAP
Try{
	$STIGID = "VCFA-9X-000331"
	$Title = "The VMware Cloud Foundation vCenter Server must have Mutual Challenge Handshake Authentication Protocol (CHAP) configured for vSAN Internet Small Computer System Interface (iSCSI) targets."
  If($rulesenabled.VCFA9X000331){
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

# VCFA-9X-000332 vSAN Key Rotation
Try{
	$STIGID = "VCFA-9X-000332"
	$Title = "The VMware Cloud Foundation vCenter Server must have new Key Encryption Keys (KEKs) reissued at regular intervals for vSAN encrypted datastore(s)."
  If($rulesenabled.VCFA9X000332){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000333 SystemConfiguration.BashShellAdministrators
Try{
	$STIGID = "VCFA-9X-000333"
	$Title = "The VMware Cloud Foundation vCenter Server must limit membership to the 'SystemConfiguration.BashShellAdministrators' Single Sign-On (SSO) group."
  If($rulesenabled.VCFA9X000333){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $groupname = "SystemConfiguration.BashShellAdministrators"
      $currentusers = Get-SsoGroup -Domain $envstigsettings.ssoDomain -Name $groupname | Get-SsoPersonUser
      $currentgroups = Get-SsoGroup -Domain $envstigsettings.ssoDomain -Name $groupname | Get-SsoGroup
      # Add builtin Administrator account to list of approved users so it doesn't get removed
      $envstigsettings.allowedBashAdminUsers += $currentusers | Where-Object {$_.Name -eq "Administrator"} | Select-Object -ExpandProperty Name
      # Add appliance management service account to list of approved users so it doesn't get removed
      $envstigsettings.allowedBashAdminUsers += $currentusers | Where-Object {$_.Name -match "vmware-applmgmtservice-"} | Select-Object -ExpandProperty Name
      # Add sddc manager service account to list of approved users so it doesn't get removed
      $envstigsettings.allowedBashAdminUsers += $currentusers | Where-Object {$_.Name -match "svc-sddc-manager-vcenter-"} | Select-Object -ExpandProperty Name
      If($currentusers.count -eq 0){
        Write-Message -Level "PASS" -Message "No users found in group: $groupname on vCenter: $vcenter."
        $unchangedcount++
      }
      Else{
        ForEach($user in $currentusers){
          If($envstigsettings.allowedBashAdminUsers.Contains($user.name)){
            Write-Message -Level "PASS" -Message "User: $($user.name) in list of approved users for Group: $groupname on vCenter: $vcenter."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Removing unapproved User: $($user.name) from Group: $groupname on vCenter: $vcenter."
            Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain $envstigsettings.ssoDomain -Name $groupname)
            $changedcount++
          }
        }
      }
      If($currentgroups.count -eq 0){
        Write-Message -Level "PASS" -Message "No groups found in group: $groupname on vCenter: $vcenter."
        $unchangedcount++
      }
      Else{
        ForEach($group in $currentgroups){
          If($envstigsettings.allowedBashAdminGroups.Contains($group.name)){
            Write-Message -Level "PASS" -Message "Group: $($group.name) in list of approved groups for Group: $groupname on vCenter: $vcenter."
            $unchangedcount++
          }
          Else{
            Write-Message -Level "CHANGED" -Message "Removing unapproved Group: $($group.name) from Group: $groupname on vCenter: $vcenter."
            Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain $envstigsettings.ssoDomain -Name $groupname)
            $changedcount++
          }
        }
      }
    }
    Else{
      Write-Message -Level "SKIPPED" -Message "This rule must reverted to default remediated manually."
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

# VCFA-9X-000334 event.maxAge and task.maxAge
Try{
	$STIGID = "VCFA-9X-000334"
	$Title = "The VMware Cloud Foundation vCenter server must have task and event retention set to at least 30 days."
  If($rulesenabled.VCFA9X000334){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = $stigsettings.eventMaxAge.Keys
      $value = [string]$stigsettings.eventMaxAge.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
      $name = $stigsettings.taskMaxAge.Keys
      $value = [string]$stigsettings.taskMaxAge.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
    }
    Else {
      $name = $defaultsettings.eventMaxAge.Keys
      $value = [string]$defaultsettings.eventMaxAge.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
      }
      $name = $defaultsettings.taskMaxAge.Keys
      $value = [string]$defaultsettings.taskMaxAge.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }Else{
        Write-Message -Level "CHANGED" -Message "Setting $name does not exist on vCenter: $vcenter. Creating setting and configuring to $value."
        New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        $changedcount++
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

# VCFA-9X-000335 Backup NKP with password
Try{
	$STIGID = "VCFA-9X-000335"
	$Title = "The VMware Cloud Foundation vCenter Server Native Key Provider must be backed up with a strong password."
  If($rulesenabled.VCFA9X000335){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000336 Published content library auth
Try{
	$STIGID = "VCFA-9X-000336"
	$Title = "The VMware Cloud Foundation vCenter Server must require authentication for published content libraries."
  If($rulesenabled.VCFA9X000336){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000337 Content library security policy
Try{
	$STIGID = "VCFA-9X-000337"
	$Title = "The VMware Cloud Foundation vCenter Server must require authentication for published content libraries."
  If($rulesenabled.VCFA9X000337){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000338 Separate authN and authZ
Try{
	$STIGID = "VCFA-9X-000338"
	$Title = "The VMware Cloud Foundation vCenter Server must separate authentication and authorization for administrators."
  If($rulesenabled.VCFA9X000338){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000339 Disable CDP/LLDP
Try{
	$STIGID = "VCFA-9X-000339"
	$Title = "The VMware Cloud Foundation vCenter Server must disable CDP/LLDP on distributed switches."
  If($rulesenabled.VCFA9X000339){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.LinkDiscoveryProtocolOperation -ne $stigsettings.dvsDiscoveryProtocolOperation){
            Write-Message -Level "CHANGED" -Message "Disabling discovery protocol operation on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $switch | Set-VDSwitch -LinkDiscoveryProtocolOperation $stigsettings.dvsDiscoveryProtocolOperation | Out-Null
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Discovery protocol operation disabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }Else{
        ForEach($switch in $dvs){
          If($switch.LinkDiscoveryProtocolOperation -ne $defaultsettings.dvsDiscoveryProtocolOperation){
            Write-Message -Level "CHANGED" -Message "Disabling discovery protocol operation on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $switch | Set-VDSwitch -LinkDiscoveryProtocolOperation $defaultsettings.dvsDiscoveryProtocolOperation | Out-Null
            $changedcount++
          }Else{
            Write-Message -Level "PASS" -Message "Discovery protocol operation disabled on Distributed Switch: $($switch.name) on vCenter: $vcenter."
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

# VCFA-9X-000340 Port Mirroring
Try{
	$STIGID = "VCFA-9X-000340"
	$Title = "The VMware Cloud Foundation vCenter Server must remove unauthorized port mirroring sessions on distributed switches."
  If($rulesenabled.VCFA9X000340){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      Else{
        ForEach($switch in $dvs){
          If(($switch.ExtensionData.Config.VspanSession).count -eq 0){
            Write-Message -Level "PASS" -Message "No port mirroring sessions found on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++
          }
          Else{
            ForEach($pmsession in $switch.ExtensionData.Config.VspanSession){
              If($envstigsettings.allowedPortMirroringSessions.Contains($pmsession.Name)){
                Write-Message -Level "PASS" -Message "Allowed port mirroring session: $($pmsession.Name) found on Distributed Switch: $($switch.name) on vCenter: $vcenter."
              }
              Else{
                Write-Message -Level "CHANGED" -Message "Removing unallowed port mirroring session: $($pmsession.Name) found on Distributed Switch: $($switch.name) on vCenter: $vcenter."
                $switchview = $switch | Get-View
                $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
                $spec.ConfigVersion = $switchview.Config.ConfigVersion
                $spec.VspanConfigSpec = New-Object VMware.Vim.VMwareDVSVspanConfigSpec
                $spec.VspanConfigSpec[0].Operation = 'remove'
                $spec.VspanConfigSpec[0].VspanSession = New-Object VMware.Vim.VMwareVspanSession
                $spec.VspanConfigSpec[0].VspanSession.Key = $pmsession.Key
                $switchview.ReconfigureDvs_Task($spec) | Out-Null
                $changedcount++  
              }            
            }
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      Else{
        ForEach($switch in $dvs){
          If(($switch.ExtensionData.Config.VspanSession).count -eq 0){
            Write-Message -Level "PASS" -Message "No port mirroring sessions found on Distributed Switch: $($switch.name) on vCenter: $vcenter."
            $unchangedcount++
          }
          Else{
            ForEach($pmsession in $switch.ExtensionData.Config.VspanSession){
              Write-Message -Level "CHANGED" -Message "Removing non-default port mirroring session: $($pmsession.Name) found on Distributed Switch: $($switch.name) on vCenter: $vcenter."
              $switchview = $switch | Get-View
              $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
              $spec.ConfigVersion = $switchview.Config.ConfigVersion
              $spec.VspanConfigSpec = New-Object VMware.Vim.VMwareDVSVspanConfigSpec
              $spec.VspanConfigSpec[0].Operation = 'remove'
              $spec.VspanConfigSpec[0].VspanSession = New-Object VMware.Vim.VMwareVspanSession
              $spec.VspanConfigSpec[0].VspanSession.Key = $pmsession.Key
              $switchview.ReconfigureDvs_Task($spec) | Out-Null
              $changedcount++            
            }
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

# VCFA-9X-000341 Port Group Overrides
Try{
	$STIGID = "VCFA-9X-000341"
	$Title = "The VMware Cloud Foundation vCenter Server must not override port group settings at the port level on distributed switches."
  If($rulesenabled.VCFA9X000341){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If(($pg.ExtensionData.Config.Policy.VlanOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed -eq $true ) -or
             ($pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.IpfixOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.MacManagementOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.ShapingOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.LivePortMovingAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.PortConfigResetAtDisconnect -eq $false) -or
             ($pg.ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed -eq $true)){
            Write-Message -Level "CHANGED" -Message "Updating Port group override settings on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
            $spec.Policy.VlanOverrideAllowed = $False
            $spec.Policy.UplinkTeamingOverrideAllowed = $False
            $spec.Policy.SecurityPolicyOverrideAllowed = $False
            $spec.Policy.IpfixOverrideAllowed = $False
            $spec.Policy.MacManagementOverrideAllowed = $False
            $spec.Policy.BlockOverrideAllowed = $True
            $spec.Policy.ShapingOverrideAllowed = $False
            $spec.Policy.VendorConfigOverrideAllowed = $False
            $spec.Policy.LivePortMovingAllowed = $False
            $spec.Policy.PortConfigResetAtDisconnect = $True
            $spec.Policy.NetworkResourcePoolOverrideAllowed = $False
            $spec.Policy.TrafficFilterOverrideAllowed = $False
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "Port group override settings correct on port group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If(($pg.ExtensionData.Config.Policy.VlanOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed -eq $true ) -or
             ($pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.IpfixOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.MacManagementOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.ShapingOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.LivePortMovingAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed -eq $true) -or
             ($pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed -eq $true)){
            Write-Message -Level "CHANGED" -Message "Updating Port group override settings on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
            $spec.Policy.VlanOverrideAllowed = $False
            $spec.Policy.UplinkTeamingOverrideAllowed = $False
            $spec.Policy.SecurityPolicyOverrideAllowed = $False
            $spec.Policy.IpfixOverrideAllowed = $False
            $spec.Policy.MacManagementOverrideAllowed = $False
            $spec.Policy.ShapingOverrideAllowed = $False
            $spec.Policy.VendorConfigOverrideAllowed = $False
            $spec.Policy.LivePortMovingAllowed = $False
            $spec.Policy.NetworkResourcePoolOverrideAllowed = $False
            $spec.Policy.TrafficFilterOverrideAllowed = $False
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "Port group override settings correct on port group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000342 Reset Port Config
Try{
	$STIGID = "VCFA-9X-000342"
	$Title = "The VMware Cloud Foundation vCenter Server must reset port configuration when virtual machines are disconnected."
  If($rulesenabled.VCFA9X000342){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If($pg.ExtensionData.Config.Policy.PortConfigResetAtDisconnect -eq $false){
            Write-Message -Level "CHANGED" -Message "Updating Port group reset at disconnect on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
            $spec.Policy.VlanOverrideAllowed = $False
            $spec.Policy.UplinkTeamingOverrideAllowed = $False
            $spec.Policy.SecurityPolicyOverrideAllowed = $False
            $spec.Policy.IpfixOverrideAllowed = $False
            $spec.Policy.MacManagementOverrideAllowed = $False
            $spec.Policy.BlockOverrideAllowed = $True
            $spec.Policy.ShapingOverrideAllowed = $False
            $spec.Policy.VendorConfigOverrideAllowed = $False
            $spec.Policy.LivePortMovingAllowed = $False
            $spec.Policy.PortConfigResetAtDisconnect = $True
            $spec.Policy.NetworkResourcePoolOverrideAllowed = $False
            $spec.Policy.TrafficFilterOverrideAllowed = $False
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "Port group reset at disconnect correct on port group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If($pg.ExtensionData.Config.Policy.PortConfigResetAtDisconnect -eq $false){
            Write-Message -Level "CHANGED" -Message "Updating Port group reset at disconnect on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
            $spec.Policy.VlanOverrideAllowed = $False
            $spec.Policy.UplinkTeamingOverrideAllowed = $False
            $spec.Policy.SecurityPolicyOverrideAllowed = $False
            $spec.Policy.IpfixOverrideAllowed = $False
            $spec.Policy.MacManagementOverrideAllowed = $False
            $spec.Policy.ShapingOverrideAllowed = $False
            $spec.Policy.VendorConfigOverrideAllowed = $False
            $spec.Policy.LivePortMovingAllowed = $False
            $spec.Policy.NetworkResourcePoolOverrideAllowed = $False
            $spec.Policy.TrafficFilterOverrideAllowed = $False
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "Port group reset at disconnect correct on port group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000343 vSAN DIT Encryption
Try{
	$STIGID = "VCFA-9X-000343"
	$Title = "The VMware Cloud Foundation vCenter Server must enable data in transit encryption for vSAN."
  If($rulesenabled.VCFA9X000343){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      Write-Message -Level "SKIPPED" -Message "This rule must be remediated manually."
      $skipcount++
    }
    Else{
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

# VCFA-9X-000344 vpxuser password length
Try{
	$STIGID = "VCFA-9X-000344"
	$Title = "The VMware Cloud Foundation vCenter Server must configure the 'vpxuser' password to meet length policy."
  If($rulesenabled.VCFA9X000344){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $name = $stigsettings.vpxdPassLength.Keys
      $value = [string]$stigsettings.vpxdPassLength.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        If($asetting.value -eq $value){
          Write-Message -Level "PASS" -Message "Setting $name is already configured correctly to $value on vCenter: $vcenter."
          $unchangedcount++
        }
        Else{
          Write-Message -Level "CHANGED" -Message "Setting $name was incorrectly set to $($asetting.value) on vCenter: $vcenter. Configuring setting to $value."
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
          $changedcount++
        }
      }
      Else{
        Write-Message -Level "PASS" -Message "Setting $name does not exist on vCenter: $vcenter. This is not a finding."
        $unchangedcount++
      }
    }
    Else {
      $name = $defaultsettings.vpxdPassLength.Keys
      $value = [string]$defaultsettings.vpxdPassLength.Values
      ## Checking to see if current setting exists
      If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
        Write-Message -Level "CHANGED" -Message "Removing setting $name on vCenter: $vcenter."
        $asetting | Remove-AdvancedSetting -Confirm:$false
        $changedcount++
      }
      Else{
        Write-Message -Level "PASS" -Message "Setting $name does not exist on vCenter: $vcenter. This is not a finding."
        $unchangedcount++
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

# VCFA-9X-000345 MAC Learning Policy
Try{
	$STIGID = "VCFA-9X-000345"
	$Title = "The VMware Cloud Foundation vCenter Server must disable the distributed port group Media Access Control (MAC) learning policy."
  If($rulesenabled.VCFA9X000345){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If($pg.ExtensionData.Config.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled -ne $stigsettings.macLearning){
            Write-Message -Level "CHANGED" -Message "Disabling MAC learning on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.DefaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
            $spec.DefaultPortConfig.MacManagementPolicy = New-Object VMware.Vim.DVSMacManagementPolicy
            $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy = New-Object VMware.Vim.DVSMacLearningPolicy
            $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled = $stigsettings.macLearning
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "MAC learning disabled on port group: $($pg.name) on vCenter: $vcenter."
            $unchangedcount++
          }
        }
      }
    }
    Else {
      If($dvs.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed switches detected on vCenter: $vcenter."
        $skipcount++
      }
      ElseIf($dvpg.count -eq 0){
        Write-Message -Level "SKIPPED" -Message "No distributed port groups detected on vCenter: $vcenter."
        $skipcount++        
      }
      Else{
        ForEach($pg in $dvpg){
          If($pg.ExtensionData.Config.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled -eq $defaultsettings.macLearning){
            Write-Message -Level "CHANGED" -Message "Updating MAC learning on port group: $($pg.name) on vCenter: $vcenter."
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.DefaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
            $spec.DefaultPortConfig.MacManagementPolicy = New-Object VMware.Vim.DVSMacManagementPolicy
            $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy = New-Object VMware.Vim.DVSMacLearningPolicy
            $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled = $defaultsettings.macLearning
            $pgview.ReconfigureDVPortgroup_Task($spec) | Out-Null
            $changedcount++
          }
          Else{
            Write-Message -Level "PASS" -Message "MAC learning disabled on port group: $($pg.name) on vCenter: $vcenter."
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

# VCFA-9X-000004 TLS Profiles. Running this last since it can interrupt the PowerCLI connection
Try{
	$STIGID = "VCFA-9X-000004"
	$Title = "The VMware Cloud Foundation vCenter Server must protect the confidentiality of network sessions."
  If($rulesenabled.VCFA9X000004){
    Write-Message -Level "INFO" -Message "Remediating STIG ID: $STIGID with Title: $Title"
    If($RevertToDefault -eq $false){
      $currentTlsProfile = Invoke-GetTlsProfilesGlobal -Confirm:$false
      If($currentTlsProfile.profile -ne $stigsettings.tlsProfile){
        Write-Message -Level "CHANGED" -Message "TLS Profile incorrectly set to $($currentTlsProfile.profile) on vCenter: $vcenter"
        Invoke-ApplianceTlsProfilesGlobalSetTask -applianceTlsProfilesGlobalSetSpec (Initialize-ApplianceTlsProfilesGlobalSetSpec -VarProfile $stigsettings.tlsProfile) -Confirm:$false
        Write-Message -Level "CHANGED" -Message "TLS Profile updated to $($stigsettings.tlsProfile) on vCenter: $vcenter. Note that this will take several minutes to complete."
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "TLS Profile set correctly to $($stigsettings.tlsProfile) on vCenter: $vcenter"
        $unchangedcount++
      }
    }
    Else{
      $currentTlsProfile = Invoke-GetTlsProfilesGlobal
      If($currentTlsProfile.profile -ne $defaultsettings.tlsProfile){
        Write-Message -Level "CHANGED" -Message "TLS Profile incorrectly set to $($currentTlsProfile.profile) on vCenter: $vcenter"
        Invoke-ApplianceTlsProfilesGlobalSetTask -applianceTlsProfilesGlobalSetSpec (Initialize-ApplianceTlsProfilesGlobalSetSpec -VarProfile $defaultsettings.tlsProfile) -Confirm:$false
        Write-Message -Level "CHANGED" -Message "TLS Profile updated to $($defaultsettings.tlsProfile) on vCenter: $vcenter. Note that this will take several minutes to complete."
        $changedcount++
      }Else{
        Write-Message -Level "PASS" -Message "TLS Profile set correctly to $($defaultsettings.tlsProfile) on vCenter: $vcenter"
        $unchangedcount++
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
Write-Message -Level "INFO" -Message "Disconnecting from vCenter SSO: $vcenter"
Disconnect-SsoAdminServer -Server $vcenter
Write-Message -Level "INFO" -Message "Stopping Powershell Transcript at $TranscriptName"
Stop-Transcript
Write-Message -Level "INFO" -Message "Generating JSON script report at $resultjson"
$summary | Out-File $resultjson
