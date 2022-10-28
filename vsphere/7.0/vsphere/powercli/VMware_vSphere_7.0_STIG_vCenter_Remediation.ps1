<# 
.SYNOPSIS 
  Remediates vCenter Server against the vSphere vCenter 7.0 STIG Readiness Guide
  Version 1 Release 4
.DESCRIPTION
  -Remediates a single host or all hosts in a specified cluster.
  -Individual controls can be enabled/disabled in the $controlsenabled hash table
  -Please review the $vcconfig below and update as appropriate for your environment
  -Not all controls are remediated by this script. Please review the output and items skipped for manual remediation.
  -VCSA-70-000016 is disabled by default. Configure a NetFlow collector IP below if needed or leave blank and enable control to remove NetFlow configuration and disable on all port groups.


.NOTES 
  File Name  : VMware_vSphere_7.0_vCenter_STIG_Remediation.ps1 
  Author     : VMware
  Version    : 1 Release 4
  License    : Apache-2.0

  Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 7.0 U3g
    -Vmware.Vsphere.SsoAdmin 1.3.2

  Example command to run script
  .\VMware_vSphere_7.0_STIG_vCenter_Remediation.ps1 -vcenter vcentername.test.local -vccred $cred -ssouser administrator@vsphere.local

  .PARAMETER vcenter
  Enter the FQDN or IP of the vCenter Server to connect to
  .PARAMETER vccred
  Enter the pscredential variable name to use for authentication to vCenter. This should be run before the script for example: $cred = get-pscredential
  .PARAMETER ssouser
  Enter the ssouser name that has permissions to perform SSO administrative tasks in vCenter.
  .PARAMETER ssopass
  Enter the sso user password. If this is not specified then it will be prompted for which is the preferred method.
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory=$true)]
  [string]$vcenter,
  [Parameter(Mandatory=$true)]
  [pscredential]$vccred,
  [Parameter(Mandatory=$true)]
  [string]$ssouser,
  [Parameter(Mandatory=$true)]
  [securestring]$ssopass,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the output report. Example /tmp")]
  [string]$reportpath,
  [Parameter(Mandatory=$false,
  HelpMessage="If Netflow is used enter the collector IP address")]
  [string]$vcNetflowCollectorIp = "",
  [Parameter(Mandatory=$false,
  HelpMessage="To disable Netflow on all port groups if enabled set to true")]
  [boolean]$vcNetflowDisableonallPortGroups = $false
)

$vcconfig = [ordered]@{
  ssoLoginAttempts     = "3"  #VCSA-70-000023
  configLogLevel       = @{"config.log.level" = "info"} #VCSA-70-000034
  ssoPasswordLength    = "15" #VCSA-70-000069
  ssoPasswordReuse     = "5"  #VCSA-70-000070
  ssoPasswordUpper     = "1"  #VCSA-70-000071
  ssoPasswordLower     = "1"  #VCSA-70-000072
  ssoPasswordNum       = "1"  #VCSA-70-000073
  ssoPasswordSpecial   = "1"  #VCSA-70-000074
  ssoPasswordLifetime  = "60" #VCSA-70-000079
  ssoFailureInterval   = "900" #VCSA-70-000145
  ssoUnlockTime        = "0"  #VCSA-70-000266
  vcNetflowCollectorIp = $vcNetflowCollectorIp   #VCSA-70-000271
  vpxdExpiration       = @{"VirtualCenter.VimPasswordExpirationInDays" = "30"} #VCSA-70-000275
  vpxdPwLength         = @{"config.vpxd.hostPasswordLength" = "32"} #VCSA-70-000276
  vpxdEventSyslog      = @{"vpxd.event.syslog.enabled" = "true"} #VCSA-70-000280
  bashAdminUsers       = @("Administrator") #VCSA-70-000290  Administrator is the only user or group by default in this group
  bashAdminGroups      = @()  #VCSA-70-000290
  trustedAdminUsers    = @() #VCSA-70-000291  No users or groups by default
  trustedAdminGroups   = @()  #VCSA-70-000291
  dbEventAge           = @{"event.maxAge" = "30"} #VCSA-70-000293
  dbTaskAge            = @{"task.maxAge" = "30"} #VCSA-70-000293
}

##### Setup report variables ####
$changedcount = 0
$unchangedcount= 0
$skipcount = 0
$failedcount = 0

##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
  VCSA7000009 = $true  #TLS 1.2
  VCSA7000023 = $true  #SSO Login Attempts
  VCSA7000024 = $true  #SSO Banner - Manual
  VCSA7000034 = $true  #config.log.level
  VCSA7000057 = $true  #Plugins - Manual
  VCSA7000059 = $true  #Identity Provider
  VCSA7000060 = $true  #MFA
  VCSA7000069 = $true  #SSO Password Length
  VCSA7000070 = $true  #SSO Password Reuse
  VCSA7000071 = $true  #SSO Password Upper
  VCSA7000072 = $true  #SSO Password Lower
  VCSA7000073 = $true  #SSO Password Number
  VCSA7000074 = $true  #SSO Password Special
  VCSA7000077 = $true  #FIPS
  VCSA7000079 = $true  #SSO Password Lifetime
  VCSA7000080 = $true  #SSO Revocation Checking
  VCSA7000089 = $true  #Session Timeout
  VCSA7000095 = $true  #User roles
  VCSA7000110 = $true  #NIOC
  VCSA7000123 = $true  #SSO Alarm
  VCSA7000145 = $true  #SSO Failed Interval
  VCSA7000148 = $true  #Syslog
  VCSA7000158 = $true  #NTP
  VCSA7000195 = $true  #DoD Cert
  VCSA7000248 = $true  #CEIP
  VCSA7000253 = $true  #SNMP v3 security
  VCSA7000265 = $true  #Disable SNMP v1/2
  VCSA7000266 = $true  #SSO unlock time
  VCSA7000267 = $true  #DVS health check
  VCSA7000268 = $true  #DVPG Forged Transmits
  VCSA7000269 = $true  #DVPG MAC Changes
  VCSA7000270 = $true  #DVPG Promiscuous mode
  VCSA7000271 = $true  #Netflow
  VCSA7000272 = $true  #Native VLAN
  VCSA7000273 = $true  #VLAN Trunking
  VCSA7000274 = $true  #Reserved VLANs
  VCSA7000275 = $true  #VPX user password change
  VCSA7000276 = $true  #VPX user password length
  VCSA7000277 = $true  #vLCM internet
  VCSA7000278 = $true  #Service Accounts
  VCSA7000279 = $true  #Isolate IP storage networks
  VCSA7000280 = $true  #Send events to syslog
  VCSA7000281 = $true  #VSAN HCL
  VCSA7000282 = $true  #VSAN Datastore name
  VCSA7000283 = $true  #Disable UN/PW and IWA
  VCSA7000284 = $true  #Crypto role
  VCSA7000285 = $true  #Crypto permissions
  VCSA7000286 = $true  #iSCSI CHAP
  VCSA7000287 = $true  #VSAN KEKs
  VCSA7000288 = $true  #LDAPS
  VCSA7000289 = $true  #LDAP Account
  VCSA7000290 = $true  #Bash admins
  VCSA7000291 = $true  #TrustedAdmins
  VCSA7000292 = $true  #Backups
  VCSA7000293 = $true  #Event Retention
  VCSA7000294 = $true  #NKP
}

Function Write-ToConsole ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details"
}

Function Write-ToConsoleRed ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Red
}

Function Write-ToConsoleGreen ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Green
}

Function Write-ToConsoleYellow ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Yellow
}

Function Write-ToConsoleBlue ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Blue
}

#Setup report output
If($reportpath){
  ## Capture Date variable
  $Date = Get-Date
  ## Start Transcript
  $TranscriptName = $reportpath + "\VMware_vSphere_7.0_STIG_ESXi_Remediation_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
  Start-Transcript -Path $TranscriptName
  ## Results file name for output to json
  $resultjson = $reportpath + "\VMware_vSphere_7.0_STIG_ESXi_Remediation_Results" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"
}

#Modules needed to run script and load
$modules = @("VMware.PowerCLI","VMware.Vsphere.SsoAdmin")

#Function to check for correct modules
Function checkModule ($m){
  if (Get-Module | Where-Object {$_.Name -eq $m}) {
    Write-ToConsole "...Module $m is already imported."
  }
  else{
    Write-ToConsole "...Trying to import module $m"
    Import-Module $m -Verbose
  }
}

#Load Modules
If($PSVersionTable.PSEdition -ne "Core"){
  Try
  {
    ForEach($module in $modules){
      Write-ToConsole "...checking for $module"
      checkModule $module
    }
  }
  Catch
  {
    Write-ToConsoleRed "Failed to load modules"
    Write-ToConsoleRed $_.Exception
    Exit -1
  }
}ElseIf($PSVersionTable.PSEdition -eq "Core"){
  ForEach($module in $modules){
    Write-ToConsole "...Core detected...checking for $module"
    checkModule $module
  }
}

#Connect to vCenter Server and SSO
Try
{
  Write-ToConsole "...Connecting to vCenter Server $vcenter"
  Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
  Write-ToConsole "...Connecting to vCenter SSO Server $vcenter"
  Connect-SsoAdminServer -Server $vcenter -User $ssouser -Password $ssopass -SkipCertificateCheck -ErrorAction Stop | Out-Null
}
Catch
{
  Write-Error "Failed to connect to $vcenter"
  Write-Error $_.Exception
  Exit -1
}

#Verify vCenter version
Try
{
  Write-ToConsole "...Verifying vCenter $vcenter is version 7.0.x"
  If(($global:DefaultVIServers | Select-Object -ExpandProperty Version).contains("7.0")){
    Write-ToConsole "...vCenter $vcenter is version $($global:DefaultVIServers | Select-Object -ExpandProperty Version) continuing..."
  } Else {
    Throw "...vCenter is not version 7.0.x...exiting..."
  }
}
Catch
{
  Write-Error $_.Exception
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Disconnect-SsoAdminServer -Server $vcenter
  Exit -1
}

#Get vcenter objects
Try{
  Write-ToConsole "...Getting PowerCLI objects for all virtual distributed switches in vCenter: $vcenter"
  $dvs = Get-VDSwitch | Sort-Object Name
  Write-ToConsole "...Getting PowerCLI objects for all virtual distributed port groups in vCenter: $vcenter"
  $dvpg = Get-VDPortgroup | Where-Object{$_.IsUplink -eq $false} | Sort-Object Name
}
Catch{
  Write-Error "...Failed to get PowerCLI objects"
  Write-Error $_.Exception
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Disconnect-SsoAdminServer -Server $vcenter
  Exit -1
}

## TLS 1.2
Try{
  $STIGID = "VCSA-70-000009"
  $Title = "The vCenter Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access."
  If($controlsenabled.VCSA7000009){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Login Attempts
Try{
  $STIGID = "VCSA-70-000023"
  $Title = "The vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user."
  If($controlsenabled.VCSA7000023){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssolockpolicies = Get-SsoLockoutPolicy
    If($ssolockpolicies.MaxFailedAttempts -ne $vcconfig.ssoLoginAttempts){
      Write-ToConsoleYellow "...SSO login attempts set incorrectly on $vcenter"
      $ssolockpolicies | Set-SsoLockoutPolicy -MaxFailedAttempts $vcconfig.ssoLoginAttempts
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO login attempts set correctly to $($vcconfig.ssoLoginAttempts) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Login Banner
Try{
  $STIGID = "VCSA-70-000024"
  $Title = "The vCenter Server must display the Standard Mandatory DoD Notice and Consent Banner before logon."
  If($controlsenabled.VCSA7000024){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Log Level
Try{
  $STIGID = "VCSA-70-000034"
  $Title = "The vCenter Server must produce audit records containing information to establish what type of events occurred."
  If($controlsenabled.VCSA7000034){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $name = $vcconfig.configLogLevel.Keys
    $value = [string]$vcconfig.configLogLevel.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
      New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
      $changedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Plugins
Try{
  $STIGID = "VCSA-70-000057"
  $Title = "The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, Web-based functionality."
  If($controlsenabled.VCSA7000057){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Identity Provider
Try{
  $STIGID = "VCSA-70-000059"
  $Title = "The vCenter Server must uniquely identify and authenticate users or processes acting on behalf of users."
  If($controlsenabled.VCSA7000059){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## MFA
Try{
  $STIGID = "VCSA-70-000060"
  $Title = "The vCenter Server must require multifactor authentication."
  If($controlsenabled.VCSA7000060){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssoauthpolicy = Get-SsoAuthenticationPolicy
    If($ssoauthpolicy.SmartCardAuthnEnabled -ne $true){
      Write-ToConsoleBlue "...!!This control must be remediated manually!!"
      $skipcount++
    }Else{
      Write-ToConsoleGreen "...SSO Smartcard login enabled on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Length
Try{
  $STIGID = "VCSA-70-000069"
  $Title = "The vCenter Server passwords must be at least 15 characters in length."
  If($controlsenabled.VCSA7000069){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.MinLength -ne $vcconfig.ssoPasswordLength){
      Write-ToConsoleYellow "...SSO password length set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -MinLength $vcconfig.ssoPasswordLength
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password length set correctly to $($vcconfig.ssoPasswordLength) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Reuse
Try{
  $STIGID = "VCSA-70-000070"
  $Title = "The vCenter Server must prohibit password reuse for a minimum of five generations."
  If($controlsenabled.VCSA7000070){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.ProhibitedPreviousPasswordsCount -ne $vcconfig.ssoPasswordReuse){
      Write-ToConsoleYellow "...SSO password reuse set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -ProhibitedPreviousPasswordsCount $vcconfig.ssoPasswordReuse
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password reuse set correctly to $($vcconfig.ssoPasswordReuse) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Upper
Try{
  $STIGID = "VCSA-70-000071"
  $Title = "The vCenter Server passwords must contain at least one uppercase character."
  If($controlsenabled.VCSA7000071){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.MinUppercaseCount -ne $vcconfig.ssoPasswordUpper){
      Write-ToConsoleYellow "...SSO password min upper characters set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -MinUppercaseCount $vcconfig.ssoPasswordUpper
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password min upper characters set correctly to $($vcconfig.ssoPasswordUpper) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Lower
Try{
  $STIGID = "VCSA-70-000072"
  $Title = "The vCenter Server passwords must contain at least one lowercase character."
  If($controlsenabled.VCSA7000072){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.MinLowercaseCount -ne $vcconfig.ssoPasswordLower){
      Write-ToConsoleYellow "...SSO password min lower characters set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -MinLowercaseCount $vcconfig.ssoPasswordLower
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password min lower characters set correctly to $($vcconfig.ssoPasswordLower) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Numbers
Try{
  $STIGID = "VCSA-70-000073"
  $Title = "The vCenter Server passwords must contain at least one numeric character."
  If($controlsenabled.VCSA7000073){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.MinNumericCount -ne $vcconfig.ssoPasswordNum){
      Write-ToConsoleYellow "...SSO password min numeric characters set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -MinNumericCount $vcconfig.ssoPasswordNum
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password min numeric characters set correctly to $($vcconfig.ssoPasswordNum) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Special
Try{
  $STIGID = "VCSA-70-000074"
  $Title = "The vCenter Server passwords must contain at least one special character."
  If($controlsenabled.VCSA7000074){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.MinSpecialCharCount -ne $vcconfig.ssoPasswordSpecial){
      Write-ToConsoleYellow "...SSO password min special characters set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -MinSpecialCharCount $vcconfig.ssoPasswordSpecial
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password min special characters set correctly to $($vcconfig.ssoPasswordSpecial) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## FIPs
Try{
  $STIGID = "VCSA-70-000077"
  $Title = "The vCenter Server must enable FIPS validated cryptography."
  If($controlsenabled.VCSA7000077){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Password Lifetime
Try{
  $STIGID = "VCSA-70-000079"
  $Title = " The vCenter Server must enforce a 60-day maximum password lifetime restriction."
  If($controlsenabled.VCSA7000079){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssopwpolicies = Get-SsoPasswordPolicy
    If($ssopwpolicies.PasswordLifetimeDays -ne $vcconfig.ssoPasswordLifetime){
      Write-ToConsoleYellow "...SSO password lifetime set incorrectly on $vcenter"
      $ssopwpolicies | Set-SsoPasswordPolicy -PasswordLifetimeDays $vcconfig.ssoPasswordLifetime
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO password lifetime set correctly to $($vcconfig.ssoPasswordLifetime) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Revocation checking
Try{
  $STIGID = "VCSA-70-000080"
  $Title = "The vCenter Server must enable revocation checking for certificate based authentication."
  If($controlsenabled.VCSA7000080){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Session timeout
Try{
  $STIGID = "VCSA-70-000089"
  $Title = "The vCenter Server must terminate vSphere Client sessions after 10 minutes of inactivity."
  If($controlsenabled.VCSA7000089){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## User roles
Try{
  $STIGID = "VCSA-70-000095"
  $Title = "The vCenter Server users must have the correct roles assigned."
  If($controlsenabled.VCSA7000095){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## NIOC
Try{
  $STIGID = "VCSA-70-000110"
  $Title = "The vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC)."
  If($controlsenabled.VCSA7000110){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter...skipping..."
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        If($switch.ExtensionData.Config.NetworkResourceManagementEnabled -eq $false){
          Write-ToConsoleYellow "...Network IO Control not enabled on $($switch.name) on $vcenter"
          ($switch | Get-View).EnableNetworkResourceManagement($true)
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Network IO Control enabled on $($switch.name) on $vcenter"
          $unchangedcount++
        }
      }
    }
  }
  Else{
    Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO Alarm
Try{
  $STIGID = "VCSA-70-000123"
  $Title = "The vCenter Server must provide an immediate real-time alert to the SA and ISSO, at a minimum, on every SSO account action."
  If($controlsenabled.VCSA7000123){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssoalarm = Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"}
    If($ssoalarm.Enabled -eq $false){
      Write-ToConsoleYellow "...Alarm for com.vmware.sso.PrincipalManagement exists on $vcenter but is not enabled...enabling..."
      $ssoalarm | Set-AlarmDefinition -Enabled $true
      $changedcount++
    }ElseIf($ssoalarm.Enabled -eq $true){
      Write-ToConsoleGreen "...Alarm for com.vmware.sso.PrincipalManagement exists on $vcenter and is enabled..."
      $unchangedcount++
    }Else{
      Write-ToConsoleYellow "...Alarm for com.vmware.sso.PrincipalManagement does not exist on $vcenter...creating..."
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
      $spec.Name = 'SSO account actions - com.vmware.sso.PrincipalManagement'
      $spec.Description = ''
      $spec.Enabled = $true
      $spec.Setting = New-Object VMware.Vim.AlarmSetting
      $spec.Setting.ToleranceRange = 0
      $spec.Setting.ReportingFrequency = 300
      $amview = Get-View -Id 'AlarmManager-AlarmManager'
      $amview.CreateAlarm($entity, $spec)
      $changedcount++
    }
  }
  Else{
    Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO fail interval
Try{
  $STIGID = "VCSA-70-000145"
  $Title = "The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes."
  If($controlsenabled.VCSA7000145){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssolockpolicies = Get-SsoLockoutPolicy
    If($ssolockpolicies.FailedAttemptIntervalSec -ne $vcconfig.ssoFailureInterval){
      Write-ToConsoleYellow "...SSO failed login interval set incorrectly on $vcenter"
      $ssolockpolicies | Set-SsoLockoutPolicy -FailedAttemptIntervalSec $vcconfig.ssoFailureInterval
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO failed login interval set correctly to $($vcconfig.ssoFailureInterval) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Syslog
Try{
  $STIGID = "VCSA-70-000148"
  $Title = "The vCenter Server must be configured to send logs to a central log server."
  If($controlsenabled.VCSA7000148){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## NTP
Try{
  $STIGID = "VCSA-70-000158"
  $Title = "The vCenter Server must compare internal information system clocks at least every 24 hours with an authoritative time server."
  If($controlsenabled.VCSA7000158){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## DoD Cert
Try{
  $STIGID = "VCSA-70-000195"
  $Title = "The vCenter Server Machine SSL certificate must be issued by a DoD certificate authority."
  If($controlsenabled.VCSA7000195){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## CEIP
Try{
  $STIGID = "VCSA-70-000248"
  $Title = "The vCenter Server must disable the Customer Experience Improvement Program (CEIP)."
  If($controlsenabled.VCSA7000248){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SNMP v3
Try{
  $STIGID = "VCSA-70-000253"
  $Title = "The vCenter server must enforce SNMPv3 security features where SNMP is required."
  If($controlsenabled.VCSA7000253){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SNMP v1/2
Try{
  $STIGID = "VCSA-70-000265"
  $Title = "The vCenter server must disable SNMPv1/2 receivers."
  If($controlsenabled.VCSA7000265){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $snmpview = Get-View -Id 'OptionManager-VpxSettings'
    $snmprecs = $snmpview.setting | Where-Object {$_.key -match 'snmp.receiver.*.enabled'}
    ForEach($snmprec in $snmprecs){
      If($snmprec.value -ne $false){
        Write-ToConsoleYellow "...$($snmprec.key) is not disabled on $vcenter"
        $updateValue = New-Object VMware.Vim.OptionValue[] (1)
        $updateValue[0] = New-Object VMware.Vim.OptionValue
        $updateValue[0].Value = $false
        $updateValue[0].Key = $snmprec.key
        $updatesnmp = Get-View -Id 'OptionManager-VpxSettings'
        $updatesnmp.UpdateOptions($updateValue)
        $changedcount++
      }Else{
        Write-ToConsoleGreen "...$($snmprec.key) is disabled on $vcenter"
        $unchangedcount++
      }
    }
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## SSO unlock time
Try{
  $STIGID = "VCSA-70-000266"
  $Title = "The vCenter Server must require an administrator to unlock an account locked due to excessive login failures."
  If($controlsenabled.VCSA7000266){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $ssolockpolicies = Get-SsoLockoutPolicy
    If($ssolockpolicies.AutoUnlockIntervalSec -ne $vcconfig.ssoUnlockTime){
      Write-ToConsoleYellow "...SSO auto unlock time set incorrectly on $vcenter"
      $ssolockpolicies | Set-SsoLockoutPolicy -AutoUnlockIntervalSec $vcconfig.ssoUnlockTime
      $changedcount++
    }Else{
      Write-ToConsoleGreen "...SSO auto unlock time set correctly to $($vcconfig.ssoUnlockTime) on $vcenter"
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## DVS Health Check
Try{
  $STIGID = "VCSA-70-000267"
  $Title = "The vCenter Server must disable the distributed virtual switch health check."
  If($controlsenabled.VCSA7000267){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        If($switch.ExtensionData.Config.HealthCheckConfig.Enable[0] -eq $true -or $switch.ExtensionData.Config.HealthCheckConfig.Enable[1] -eq $true){
          Write-ToConsoleYellow "...Health check enabled on $($switch.name) on $vcenter"
          ($switch | Get-View).UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Health check disabled on $($switch.name) on $vcenter"
          $unchangedcount++
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
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Reject forged transmits
Try{
  $STIGID = "VCSA-70-000268"
  $Title = "The vCenter Server must set the distributed port group Forged Transmits policy to reject."
  If($controlsenabled.VCSA7000268){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        $policy = $switch | Get-VDSecurityPolicy
        If($policy.ForgedTransmits -eq $true){
          Write-ToConsoleYellow "...Forged Transmits enabled on $($switch.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -ForgedTransmits $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Forged Transmits disabled on $($switch.name) on $vcenter"
          $unchangedcount++
        }
      }
      ForEach($pg in $dvpg){
        $policy = $pg | Get-VDSecurityPolicy
        If($policy.ForgedTransmits -eq $true){
          Write-ToConsoleYellow "...Forged Transmits enabled on $($pg.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -ForgedTransmits $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Forged Transmits disabled on $($pg.name) on $vcenter"
          $unchangedcount++
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
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## MacChanges
Try{
  $STIGID = "VCSA-70-000269"
  $Title = "The vCenter Server must set the distributed port group MAC Address Change policy to reject."
  If($controlsenabled.VCSA7000269){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        $policy = $switch | Get-VDSecurityPolicy
        If($policy.MacChanges -eq $true){
          Write-ToConsoleYellow "...MAC Changes enabled on $($switch.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -MacChanges $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...MAC Changes disabled on $($switch.name) on $vcenter"
          $unchangedcount++
        }
      }
      ForEach($pg in $dvpg){
        $policy = $pg | Get-VDSecurityPolicy
        If($policy.MacChanges -eq $true){
          Write-ToConsoleYellow "...MAC Changes enabled on $($pg.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -MacChanges $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...MAC Changes disabled on $($pg.name) on $vcenter"
          $unchangedcount++
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
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## promiscious mode
Try{
  $STIGID = "VCSA-70-000270"
  $Title = "The vCenter Server must set the distributed port group Promiscuous Mode policy to reject."
  If($controlsenabled.VCSA7000270){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        $policy = $switch | Get-VDSecurityPolicy
        If($policy.AllowPromiscuous -eq $true){
          Write-ToConsoleYellow "...Promiscious Mode enabled on $($switch.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Promiscious Mode disabled on $($switch.name) on $vcenter"
          $unchangedcount++
        }
      }
      ForEach($pg in $dvpg){
        $policy = $pg | Get-VDSecurityPolicy
        If($policy.AllowPromiscuous -eq $true){
          Write-ToConsoleYellow "...Promiscious Mode enabled on $($pg.name) on $vcenter"
          $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Promiscious Mode disabled on $($pg.name) on $vcenter"
          $unchangedcount++
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
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Net Flow
Try{
  $STIGID = "VCSA-70-000271"
  $Title = "The vCenter Server must only send NetFlow traffic to authorized collectors."
  If($controlsenabled.VCSA7000271){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
      ForEach($switch in $dvs){
        If($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress -ne $vcconfig.vcNetflowCollectorIp){
          Write-ToConsoleYellow "...Unknown NetFlow collector on $($switch.name) on $vcenter"
          $switchview = $switch | Get-View
          $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
          $spec.configversion = $switchview.Config.ConfigVersion
          $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
          $spec.IpfixConfig.CollectorIpAddress = $vcconfig.vcNetflowCollectorIp
          $spec.IpfixConfig.CollectorPort = "0"
          $spec.IpfixConfig.ObservationDomainId = "0"
          $spec.IpfixConfig.ActiveFlowTimeout = "60"
          $spec.IpfixConfig.IdleFlowTimeout = "15"
          $spec.IpfixConfig.SamplingRate = "4096"
          $spec.IpfixConfig.InternalFlowsOnly = $False
          $switchview.ReconfigureDvs_Task($spec)
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...No unknown NetFlow collectors configured on $($switch.name) on $vcenter"
          $unchangedcount++
        }
      }
      If($vcNetflowDisableonallPortGroups){
        ForEach($pg in $dvpg){
          If($pg.ExtensionData.Config.DefaultPortConfig.IpfixEnabled.value -eq $true){
            Write-ToConsoleRed "...NetFlow collection enabled on $($pg.name) on $vcenter"
            $pgview = $pg | Get-View
            $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
            $spec.configversion = $pgview.Config.ConfigVersion
            $spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
            $spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
            $spec.defaultPortConfig.ipfixEnabled.inherited = $true
            $spec.defaultPortConfig.ipfixEnabled.value = $false
            $pgview.ReconfigureDVPortgroup_Task($spec)
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...NetFlow collection disabled on $($pg.name) on $vcenter"
            $unchangedcount++
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
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Native VLAN
Try{
  $STIGID = "VCSA-70-000272"
  $Title = "The vCenter Server must configure all port groups to a value other than that of the native VLAN."
  If($controlsenabled.VCSA7000272){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VLAN Trunking
Try{
  $STIGID = "VCSA-70-000273"
  $Title = "The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized."
  If($controlsenabled.VCSA7000273){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Reserved VLANs
Try{
  $STIGID = "VCSA-70-000274"
  $Title = "The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches."
  If($controlsenabled.VCSA7000274){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    If($dvs.count -eq 0){
      Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
      $skipcount++
    }Else{
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VPXD PW
Try{
  $STIGID = "VCSA-70-000275"
  $Title = "The vCenter Server must configure the vpxuser auto-password to be changed every 30 days."
  If($controlsenabled.VCSA7000275){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $name = $vcconfig.vpxdExpiration.Keys
    $value = [string]$vcconfig.vpxdExpiration.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
      New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
      $changedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VPXD PW Length
Try{
  $STIGID = "VCSA-70-000276"
  $Title = "The vCenter Server must configure the vpxuser password meets length policy."
  If($controlsenabled.VCSA7000276){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $name = $vcconfig.vpxdPwLength.Keys
    $value = [string]$vcconfig.vpxdPwLength.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleGreen "...Setting $name does not exist on $vcenter and is not a finding..."
      $unchangedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## vLCM
Try{
  $STIGID = "VCSA-70-000277"
  $Title = "The vCenter Server must be isolated from the public Internet but must still allow for patch notification and delivery."
  If($controlsenabled.VCSA7000277){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Service accounts
Try{
  $STIGID = "VCSA-70-000278"
  $Title = "The vCenter Server must use unique service accounts when applications connect to vCenter."
  If($controlsenabled.VCSA7000278){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Isolate IP based storage
Try{
  $STIGID = "VCSA-70-000279"
  $Title = "The vCenter Server must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
  If($controlsenabled.VCSA7000279){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Send events to syslog
Try{
  $STIGID = "VCSA-70-000280"
  $Title = "The vCenter server must be configured to send events to a central log server."
  If($controlsenabled.VCSA7000280){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $name = $vcconfig.vpxdEventSyslog.Keys
    $value = [string]$vcconfig.vpxdEventSyslog.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
      New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
      $changedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VSAN HCL
Try{
  $STIGID = "VCSA-70-000281"
  $Title = "The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server."
  If($controlsenabled.VCSA7000281){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VSAN Datastore names
Try{
  $STIGID = "VCSA-70-000282"
  $Title = "The vCenter Server must configure the vSAN Datastore name to a unique name."
  If($controlsenabled.VCSA7000282){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $vsandatastores = Get-Datastore | Where-Object {$_.type -match "vsan"}
    If($vsandatastores.count -eq 0){
      Write-ToConsoleBlue "...No VSAN datastores detected on $vcenter"
      $skipcount++
    }Else{
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
    }
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Disable UN/PW and IWA
Try{
  $STIGID = "VCSA-70-000283"
  $Title = "The vCenter Server must disable Username/Password and Windows Integrated Authentication."
  If($controlsenabled.VCSA7000283){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Crypto role
Try{
  $STIGID = "VCSA-70-000284"
  $Title = "The vCenter Server must restrict access to the cryptographic role."
  If($controlsenabled.VCSA7000284){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Crypto permissions
Try{
  $STIGID = "VCSA-70-000285"
  $Title = "The vCenter Server must restrict access to cryptographic permissions."
  If($controlsenabled.VCSA7000285){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## iSCSI CHAP
Try{
  $STIGID = "VCSA-70-000286"
  $Title = "The vCenter Server must have Mutual CHAP configured for vSAN iSCSI targets."
  If($controlsenabled.VCSA7000286){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## VSAN KEKs
Try{
  $STIGID = "VCSA-70-000287"
  $Title = "The vCenter Server must have new Key Encryption Keys (KEKs) re-issued at regular intervals for vSAN encrypted datastore(s)."
  If($controlsenabled.VCSA7000287){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## LDAPS
Try{
  $STIGID = "VCSA-70-000288"
  $Title = "The vCenter Server must use LDAPS when adding an LDAP identity source."
  If($controlsenabled.VCSA7000288){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## LDAP Account
Try{
  $STIGID = "VCSA-70-000289"
  $Title = "The vCenter Server must use a limited privilege account when adding an LDAP identity source."
  If($controlsenabled.VCSA7000289){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Bash Admin Group
Try{
  $STIGID = "VCSA-70-000290"
  $Title = "The vCenter Server must limit membership to the SystemConfiguration.BashShellAdministrators SSO group."
  If($controlsenabled.VCSA7000290){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $groupname = "SystemConfiguration.BashShellAdministrators"
    $users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
    $groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
    ForEach($user in $users){
      If($vcconfig.bashAdminUsers.Contains($user.name)){
        Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...User: $($user.name) in not approved...removing..."
        Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
        $changedcount++
      }
    }
    ForEach($group in $groups){
      If($vcconfig.bashAdminGroups.Contains($group.name)){
        Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Group: $($group.name) in not approved...removing..."
        Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
        $changedcount++
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Trusted Admin Group
Try{
  $STIGID = "VCSA-70-000291"
  $Title = "The vCenter Server must limit membership to the TrustedAdmins SSO group."
  If($controlsenabled.VCSA7000291){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $groupname = "TrustedAdmins"
    $users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
    $groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
    ForEach($user in $users){
      If($vcconfig.trustedAdminUsers.Contains($user.name)){
        Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...User: $($user.name) in not approved...removing..."
        Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
        $changedcount++
      }
    }
    ForEach($group in $groups){
      If($vcconfig.trustedAdminGroups.Contains($group.name)){
        Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Group: $($group.name) in not approved...removing..."
        Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
        $changedcount++
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Backups
Try{
  $STIGID = "VCSA-70-000292"
  $Title = "The vCenter server configuration must be backed up on a regular basis."
  If($controlsenabled.VCSA7000292){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## Task Retention
Try{
  $STIGID = "VCSA-70-000293"
  $Title = "vCenter task and event retention must be set to at least 30 days."
  If($controlsenabled.VCSA7000293){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    $name = $vcconfig.dbEventAge.Keys
    $value = [string]$vcconfig.dbEventAge.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
      New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
      $changedcount++
    }
    $name = $vcconfig.dbTaskAge.Keys
    $value = [string]$vcconfig.dbTaskAge.Values
    ## Checking to see if current setting exists
    If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
      If($asetting.value -eq $value){
        Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        $changedcount++
      }
    }Else{
      Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
      New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
      $changedcount++
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

## NKP
Try{
  $STIGID = "VCSA-70-000294"
  $Title = "vCenter Native Key Providers must be backed up with a strong password."
  If($controlsenabled.VCSA7000294){
    Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
    Write-ToConsoleBlue "...!!This control must be remediated manually!!"
    $skipcount++
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
  Write-Error $_.Exception
  $failedcount++
}

$summary = New-Object PSObject -Property ([ordered]@{
  "vcenter" = $vcenter
  "reportpath" = $reportpath
  "ok" = $unchangedcount
  "changed" = $changedcount
  "skipped" = $skipcount
  "failed" = $failedcount
  "inputs" = $vcconfig
  "controlsenabled" = $controlsenabled
})
$summary = $summary | ConvertTo-Json
Write-ToConsole "...Configuration Summary:"
Write-ToConsole $summary
Write-ToConsole "...Script Complete...Disconnecting from vCenter $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
Disconnect-SsoAdminServer -Server $vcenter

#Output run results to file
If($reportpath){
  Stop-Transcript
  ## Results file name for output to json
  $summary | Out-File $resultjson
}