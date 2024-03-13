<# 
.SYNOPSIS 
  Remediates ESXi hosts against the vSphere ESXi 8.0 STIG Readiness Guide
  Version 1 Release 1
.DESCRIPTION
  -Remediates a single host or all hosts in a specified cluster.
  -Individual controls can be enabled/disabled in the $controlsenabled hash table
  -SSH settings are not remediated by this script since they are correct OOTB.
  -Not all controls are remediated by this script. Please review the output and items skipped for manual remediation.
  -This script is intented for internal purposes to harden test beds for functional testing.

.NOTES 
  File Name  : VMware_vSphere_8.0_STIG_ESXi_Remediation.ps1 
  Author     : VMware
  Version    : 1 Release 1
  License    : Apache-2.0

  Tested against
  -PowerCLI 13
  -Powershell 5/Core 7.3.4
  -vCenter/ESXi 8.0 U1a

  Example command to run script
  .\VMware_vSphere_8.0_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local -vccred $cred -esxAdminGroup "esxAdmins2" -allowedIPs "10.0.0.0/8" -syslogServer "tcp://log.test.local:514" -ntpServers "time.test.local","time2.test.local" -reportpath C:\Reports

  .PARAMETER vcenter
  Enter the FQDN or IP of the vCenter Server to connect to
  .PARAMETER vccred
  Enter the pscredential variable name to use for authentication to vCenter. This should be run before the script for example: $cred = get-pscredential 
  .PARAMETER hostname
  Enter the hostname of a single ESXi host to remediate
  .PARAMETER cluster
  Enter the cluster name of a vSphere cluster to remediate all hosts in a targeted cluster
  .PARAMETER reportpath
  Enter the path for the output report. Example /tmp
  .PARAMETER esxAdminGroup
  Enter the Active Directory Admins group to use for administrative access to ESXi
  .PARAMETER allowedIPs
  Enter allowed IP ranges for the ESXi firewall in comma separated format.  For Example "192.168.0.0/16","10.0.0.0/8"
  .PARAMETER syslogServer
  Enter the syslog server for the ESXi server(s). Example tcp://log.domain.local:514
  .PARAMETER logInsight
  Enable this option if VMware vRealize Log Insight is used to manage syslog on the ESXi host(s).
  .PARAMETER ntpServers
  Enter NTP servers.  For Example "10.1.1.1","10.1.1.2"
  .PARAMETER nativeVLAN
  Specify the native VLAN Id configured on the ports going to the ESXi Hosts.  If none is specified the default of 1 will be used.
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory=$true)]
  [string]$vcenter,
  [Parameter(Mandatory=$true)]
  [pscredential]$vccred,
  [Parameter(Mandatory=$true,ParameterSetName="hostname")]
  [string]$hostname,
  [Parameter(Mandatory=$true,ParameterSetName="cluster")]
  [string]$cluster,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the output report. Example /tmp")]
  [string]$reportpath,  
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the Active Directory Admins group to use for administrative access to ESXi")]
  [string]$esxAdminGroup,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter allowed IP ranges for the ESXi firewall in comma separated format.  For Example `"192.168.0.0/16`",`"10.0.0.0/8`" ")]
  [string[]]$allowedIPs,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the syslog server for the ESXi server(s). Example tcp://log.domain.local:514")]
  [string]$syslogServer,
  [Parameter(Mandatory=$false,
  HelpMessage="Enable this option if VMware vRealize Log Insight is used to manage syslog on the ESXi host(s).")]
  [switch]$logInsight,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter NTP servers.  For Example `"10.1.1.1`",`"10.1.1.2`" ")]
  [string[]]$ntpServers,
  [Parameter(Mandatory=$false,
  HelpMessage="Specify the native VLAN Id configured on the ports going to the ESXi Hosts.  If none is specified the default of 1 will be used.")]
  [string]$nativeVLAN = "1"
)

##### Default STIG Values #####
$stigsettings = [ordered]@{
  accountLockFailures     = @{"Security.AccountLockFailures" = "3"} #ESXI-80-000005
  lockdownlevel           = "lockdownNormal"  #ESXI-80-000008	Lockdown level.  lockdownDisabled,lockdownNormal,lockdownStrict
  hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "900"} #ESXI-80-000010
  logLevel                = @{"Config.HostAgent.log.level" = "info"} #ESXI-80-000015
  passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-80-000035
  passwordHistory         = @{"Security.PasswordHistory" = "5"} #ESXI-80-000043
  enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} #ESXI-80-000047
  shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "900"} #ESXI-80-000068
  accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} #ESXI-80-000111
  auditRecordStorageCap   = @{"Syslog.global.auditRecord.storageCapacity" = "100"} #ESXI-80-000113
  vibacceptlevel          = "PartnerSupported"  #ESXI-80-000133 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
  sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"} #ESXI-80-000161
  DCUIAccess              = @{"DCUI.Access" = "root"}  #ESXI-80-000189
  sshEnabled              = $false #ESXI-80-000193
  shellEnabled            = $false #ESXI-80-000194
  shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"} #ESXI-80-000195
  DCUITImeout             = @{"UserVars.DcuiTimeOut" = "600"} #ESXI-80-000196
  ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"} #ESXI-80-000213
  BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"} #ESXI-80-000215
  DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} #ESXI-80-000219
  esxiLatestBuild         = "20513097" #ESXI-80-000221
  suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} #ESXI-80-000222
  suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} #ESXI-80-000223
  syslogCertCheck         = @{"Syslog.global.logCheckSSLCerts" = "true"} #ESXI-80-000224
  memEagerZero            = @{"Mem.MemEagerZero" = "1"} #ESXI-80-000225
  apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-80-000226
  passwordMaxAge          = @{"Security.PasswordMaxDays" = "90"} #ESXI-80-000227
  cimEnabled              = $false #ESXI-80-000228
  slpdEnabled             = $false #ESXI-80-000231
  syslogAuditEnable       = @{"Syslog.global.auditRecord.storageEnable" = $true} #ESXI-80-000232
  syslogAuditRemote       = @{"Syslog.global.auditRecord.remoteEnable" = $true} #ESXI-80-000233
  syslogCertStrict        = @{"Syslog.global.certificate.strictX509Compliance" = $true} #ESXI-80-000234
  syslogLogLevel          = @{"Syslog.global.logLevel" = "info"} #ESXI-80-000235
  executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"} #ESXI-80-000244
  ##### Environment Specific STIG Values #####
  syslogHost              = @{"Syslog.global.logHost" = $syslogServer}   #ESXI-80-000114
  ntpServers              = $ntpServers #ESXI-80-000124
  issueBanner             = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
  allowedips              = $allowedIPs  #ESXI-80-000239 Allows IP ranges for the ESXi firewall
  esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup} #ESXI-80-000241
  syslogScratch           = @{"Syslog.global.logDir" = "[] /scratch/log"} #ESXI-80-000243
}

#ESXI-80-000006
$welcomeBanner = @"
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}	{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:         {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      enforcement (LE), and counterintelligence (CI) investigations.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     At any time, the USG may inspect and seize data stored on this IS.                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Communications using, or data stored on, this IS are not private, are subject to routine monitoring,      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      interception, and search, and may be disclosed or used for any USG-authorized purpose.              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      for your personal benefit or privacy.                                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      product are private and confidential. See User Agreement for details.                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
"@

##### Setup report variables ####
$changedcount = 0
$unchangedcount= 0
$skipcount = 0
$failedcount = 0

##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
  ESXI80000005 = $true  #Account Lock Failures
  ESXI80000006 = $true  #Consent Banner Welcome
  ESXI80000008 = $true  #Lockdown Mode
  ESXI80000010 = $true  #Host Client Timeout
  ESXI80000014 = $true  #SSH FipsMode
  ESXI80000015 = $true  #Log Level
  ESXI80000035 = $true  #Password Complexity
  ESXI80000043 = $true  #Password History
  ESXI80000047 = $true  #Disable Mob
  ESXI80000049 = $true  #Active Directory
  ESXI80000052 = $true  #SSH IgnoreRhosts yes
  ESXI80000068 = $true  #Shell Interactive Timeout
  ESXI80000085 = $true  #Secure boot enforcement
  ESXI80000094 = $true  #Secureboot
  ESXI80000111 = $true  #Account Unlock Time
  ESXI80000113 = $true  #Audit Storage Capacity
  ESXI80000114 = $true  #Syslog
  ESXI80000124 = $true  #NTP
  ESXI80000133 = $true  #Acceptance Level
  ESXI80000145 = $true  #iSCSI CHAP
  ESXI80000160 = $true  #Isolate vMotion
  ESXI80000161 = $true  #TLS 1.2
  ESXI80000187 = $true  #SSH ciphers
  ESXI80000189 = $true  #DCUI.Access List
  ESXI80000191 = $true  #Consent Banner /etc/issue
  ESXI80000192 = $true  #SSH Banner
  ESXI80000193 = $true  #SSH Disabled
  ESXI80000194 = $true  #Shell Disabled
  ESXI80000195 = $true  #Shell Timeout
  ESXI80000196 = $true  #DCUI Timeout
  ESXI80000198 = $true  #Isolate Management
  ESXI80000199 = $true  #Isolate Storage traffic
  ESXI80000201 = $true  #Lockdown Mode Exceptions
  ESXI80000202 = $true  #SSH HostbasedAuthentication no
  ESXI80000203 = $true  #SSH PermitEmptyPasswords no
  ESXI80000204 = $true  #SSH PermitUserEnvironment no
  ESXI80000205 = $true  #SSH StrictModes yes
  ESXI80000206 = $true  #SSH Compression no
  ESXI80000207 = $true  #SSH GatewayPorts no
  ESXI80000208 = $true  #SSH X11Forwarding no
  ESXI80000209 = $true  #SSH PermitTunnel no
  ESXI80000210 = $true  #SSH ClientAliveCountMax 3
  ESXI80000211 = $true  #SSH ClientAliveInterval 200
  ESXI80000212 = $true  #SNMP
  ESXI80000213 = $true  #Memory Salting
  ESXI80000214 = $true  #Default Firewall
  ESXI80000215 = $true  #BPDU
  ESXI80000216 = $true  #Forged Transmits
  ESXI80000217 = $true  #MAC Changes
  ESXI80000218 = $true  #Prom Mode
  ESXI80000219 = $true  #dvFilter
  ESXI80000220 = $true  #VLAN 4095
  ESXI80000221 = $true  #Patch Level
  ESXI80000222 = $true  #Suppress Shell Warning
  ESXI80000223 = $true  #Suppress Hyperthreading Warning
  ESXI80000224 = $true  #Syslog Cert Verification
  ESXI80000225 = $true  #mem eagerzero
  ESXI80000226 = $true  #API Timeout
  ESXI80000227 = $true  #Password age
  ESXI80000228 = $true  #CIM service disabled
  ESXI80000229 = $true  #DoD Cert
  ESXI80000230 = $true  #SSH AllowTCPForwarding
  ESXI80000231 = $true  #Disable SLPD Service
  ESXI80000232 = $true  #Syslog audit enable
  ESXI80000233 = $true  #Syslog audit remote
  ESXI80000234 = $true  #Syslog x509 strict
  ESXI80000235 = $true  #Syslog log level
  ESXI80000236 = $true  #VM Override
  ESXI80000237 = $true  #Vm Override Logger
  ESXI80000238 = $true  #TPM Config encryption
  ESXI80000239 = $true  #Firewall Rules
  ESXI80000240 = $true  #Authentication Proxy
  ESXI80000241 = $true  #SSH PermitRootLogin no
  ESXI80000243 = $true  #Persistent Logs
  ESXI80000244 = $true  #execute approved vibs
  ESXI80000245 = $true  #entropy
  ESXI80000246 = $true  #log filtering
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
  $TranscriptName = $reportpath + "\VMware_vSphere_8.0_STIG_ESXi_Remediation_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
  Start-Transcript -Path $TranscriptName
  ## Results file name for output to json
  $resultjson = $reportpath + "\VMware_vSphere_8.0_STIG_ESXi_Remediation_Results" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"   
}

#Modules needed to run script and load
$modules = @("VMware.PowerCLI")

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

#Connect to vCenter
Try
{
  Write-ToConsole "...Connecting to vCenter $vcenter"
  Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
}
Catch
{
  Write-ToConsoleRed "Failed to connect to $vcenter"
  Write-ToConsoleRed $_.Exception
  Exit -1
}

#Gather Info
Try
{
  Write-ToConsole "...Gathering info on target hosts in $vcenter"
  If($hostname){
    $vmhosts = Get-VMHost -Name $hostname -ErrorAction Stop | Sort-Object Name
    $vmhostsv = $vmhosts | Get-View -ErrorAction Stop | Sort-Object Name 
    ForEach($vmhost in $vmhosts){
      Write-ToConsole "...Found host $vmhost"
    }
  }
  If($cluster){
    $vmhosts = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object Name
    $vmhostsv = $vmhosts | Get-View | Sort-Object Name
    ForEach($vmhost in $vmhosts){
      Write-ToConsole "...Found host $vmhost"
    }
  } 
}
Catch
{
  Write-ToConsoleRed "Failed to gather information on target hosts in $vcenter"
  Write-ToConsoleRed $_.Exception
  Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Exit -1
}

## Account Lock Failures
Try{
	$STIGID = "ESXI-80-000005"
	$Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
  If($controlsenabled.ESXI80000005){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.accountLockFailures.Keys
      $value = [string]$stigsettings.accountLockFailures.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Welcome banner   Disabling for internal use case
Try{
	$STIGID = "ESXI-80-000006"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via the DCUI."
  If($controlsenabled.ESXI80000006){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = "Annotations.WelcomeMessage"
      $value = $welcomeBanner
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Host Client timeout
Try{
	$STIGID = "ESXI-80-000010"
	$Title = "The ESXi host client must be configured with an idle session timeout."
  If($controlsenabled.ESXI80000010){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.hostClientTimeout.Keys
      $value = [string]$stigsettings.hostClientTimeout.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## SSH FIPS
Try{
	$STIGID = "ESXI-80-000014"
	$Title = "The ESXi host SSH daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
  If($controlsenabled.ESXI80000014){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      $results = $esxcli.system.security.fips140.ssh.get.invoke()
      If($results -ne "true"){
        Write-ToConsoleGreen "...SSH FIPS Mode set correctly to $results on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring SSH FIPS Mode on $($vmhost.name)"
        $fipsargs = $esxcli.system.security.fips140.ssh.set.CreateArgs()
        $fipsargs.enable = $true
        $esxcli.system.security.fips140.ssh.set.Invoke($fipsargs)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Log Level
Try{
	$STIGID = "ESXI-80-000015"
	$Title = "The ESXi must produce audit records containing information to establish what type of events occurred."
  If($controlsenabled.ESXI80000015){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.logLevel.Keys
      $value = [string]$stigsettings.logLevel.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Password Complexity
Try{
	$STIGID = "ESXI-80-000035"
	$Title = "The ESXi host must enforce password complexity by configuring a password quality policy."
  If($controlsenabled.ESXI80000035){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.passwordComplexity.Keys
      $value = [string]$stigsettings.passwordComplexity.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Password History
Try{
	$STIGID = "ESXI-80-000043"
	$Title = "The ESXi host must prohibit password reuse for a minimum of five generations."
  If($controlsenabled.ESXI80000043){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.passwordHistory.Keys
      $value = [string]$stigsettings.passwordHistory.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## MOB
Try{
	$STIGID = "ESXI-80-000047"
	$Title = "The ESXi host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB)."
  If($controlsenabled.ESXI80000047){
  Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
  ForEach($vmhost in $vmhosts){
    $name = $stigsettings.enableMob.Keys
    $value = [System.Convert]::ToBoolean([String]$stigsettings.enableMob.Values)
    ## Checking to see if current setting exists
    If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
    If($asetting.value -eq $value){
      Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
      $unchangedcount++
    }Else{
      Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
      $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
      $changedcount++
    }
    }Else{
    Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
    $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Active Directory
Try{
	$STIGID = "ESXI-80-000049"
	$Title = "The ESXi host must uniquely identify and must authenticate organizational users by using Active Directory."
  If($controlsenabled.ESXI80000049){
  Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
  $skipcount++
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

## SSH .rhosts
Try{
	$STIGID = "ESXI-80-000052"
	$Title = "The ESXi host SSH daemon must ignore .rhosts files."
  If($controlsenabled.ESXI80000052){
  Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
  $skipcount++
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

## Shell Interactive Timeout
Try{
	$STIGID = "ESXI-80-000068"
	$Title = "The ESXi host must set a timeout to automatically end idle shell sessions after fifteen minutes."
  If($controlsenabled.ESXI80000068){
  Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
  ForEach($vmhost in $vmhosts){
    $name = $stigsettings.shellIntTimeout.Keys
    $value = [string]$stigsettings.shellIntTimeout.Values
    ## Checking to see if current setting exists
    If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
    If($asetting.value -eq $value){
      Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
      $unchangedcount++
    }Else{
      Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
      $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
      $changedcount++
    }
    }Else{
    Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
    $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Require Secure Boot
Try{
	$STIGID = "ESXI-80-000085"
	$Title = "The ESXi host must implement Secure Boot enforcement."
  If($controlsenabled.ESXI80000085){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      $results = $esxcli.system.settings.encryption.get.invoke()
      If($results.RequireSecureBoot -eq "true"){
        Write-ToConsoleGreen "...Secure Boot required set correctly to $($results.RequireSecureBoot) on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring Secure Boot required on $($vmhost.name)"
        $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
        $sbarg.requiresecureboot = $true
        $esxcli.system.settings.encryption.set.Invoke($sbarg)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Secure Boot
Try{
	$STIGID = "ESXI-80-000094"
	$Title = "The ESXi host must enable Secure Boot."
  If($controlsenabled.ESXI80000094){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## Account Unlock Timeout
Try{
	$STIGID = "ESXI-80-000111"
	$Title = "The ESXi host must enforce an unlock timeout of 15 minutes after a user account is locked out."
  If($controlsenabled.ESXI80000111){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.accountUnlockTime.Keys
      $value = [string]$stigsettings.accountUnlockTime.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Audit Record Capacity
Try{
	$STIGID = "ESXI-80-000113"
	$Title = "The ESXi host must allocate audit record storage capacity to store at least one weeks worth of audit records."
  If($controlsenabled.ESXI80000113){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.auditRecordStorageCap.Keys
      $value = [string]$stigsettings.auditRecordStorageCap.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Syslog
Try{
	$STIGID = "ESXI-80-000114"
	$Title = "The ESXi host must off-load logs via syslog."
  If($controlsenabled.ESXI80000114){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($logInsight){
      Write-ToConsole "...Log Insight used to manage syslog skipping this control"
      $skipcount++
    }Else{
      ForEach($vmhost in $vmhosts){
        $name = $stigsettings.syslogHost.Keys
        $value = [string]$stigsettings.syslogHost.Values
        ## Checking to see if current setting exists
        If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
          If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
            $unchangedcount++
          }Else{
            Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
            $changedcount++
          }
        }Else{
          Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
          $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
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
  Write-ToConsoleRed "Failed to remediate STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# NTP
Try{
	$STIGID = "ESXI-80-000124"
	$Title = "The ESXi host must synchronize internal information system clocks to the authoritative time source."
  If($controlsenabled.ESXI80000124){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $currentntp = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
      If($currentntp.count -eq "0"){
        Write-ToConsoleYellow "...No NTP servers configured on $($vmhost.name)...configuring NTP"
        $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers -ErrorAction Stop
        $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On -ErrorAction Stop | Out-Null
        $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService -ErrorAction Stop | Out-Null
        $changedcount++
      }
      else{
        If($stigsettings.ntpServers[0] -ne $currentntp[0] -or $stigsettings.ntpServers[1] -ne $currentntp[1]){
          Write-ToConsoleYellow "...NTP Servers configured incorrectly on $($vmhost.name)...reconfiguring NTP"
          ForEach($ntp in $currentntp){
            $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false -ErrorAction Stop
          }
          $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers -ErrorAction Stop
          $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On -ErrorAction Stop | Out-Null
          $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService -ErrorAction Stop | Out-Null
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...NTP Servers configured Correctly on $($vmhost.name)"
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VIB Acceptance
Try{
	$STIGID = "ESXI-80-000133"
	$Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) Acceptance Levels must be verified."
  If($controlsenabled.ESXI80000133){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      $results = $esxcli.software.acceptance.get.Invoke()
      If($results -ne "CommunitySupported"){
        Write-ToConsoleGreen "...VIB Acceptance level is set correctly to $results on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring VIB Acceptance level to $($stigsettings.vibacceptlevel) on $($vmhost.name)"
        $vibargs = $esxcli.software.acceptance.set.CreateArgs()
        $vibargs.level = $stigsettings.vibacceptlevel
        $esxcli.software.acceptance.set.Invoke($vibargs)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# iSCSI CHAP
Try{
	$STIGID = "ESXI-80-000145"
	$Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
  If($controlsenabled.ESXI80000145){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# vMotion Separation
Try{
	$STIGID = "ESXI-80-000160"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
  If($controlsenabled.ESXI80000160){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
      ForEach($vmk in $vmks){
        If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereReplicationEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereReplicationNFCEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VSphereBackupNFCEnabled -eq "True")){
          Write-ToConsoleRed "...VMKernel $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name).  Investigate and separate functions to another network and VMKernel."
          $failedcount++
        }ElseIf($vmk.VMotionEnabled -eq "True"){
          Write-ToConsoleGreen "...VMKernel $($vmk.name) appears to have vMotion only enabled on $($vmhost.name)"
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# TLS 1.2
Try{
	$STIGID = "ESXI-80-000161"
	$Title = "The ESXi host must maintain the confidentiality and integrity of information during transmission by exclusively enabling TLS 1.2."
  If($controlsenabled.ESXI80000161){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.sslProtocols.Keys
      $value = [string]$stigsettings.sslProtocols.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## SSH Ciphers
Try{
	$STIGID = "ESXI-80-000187"
	$Title = "The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers."
  If($controlsenabled.ESXI80000187){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## DCUI.Access
Try{
	$STIGID = "ESXI-80-000189"
	$Title = "The ESXi host DCUI.Access list must be verified."
  If($controlsenabled.ESXI80000189){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.DCUIAccess.Keys
      $value = $stigsettings.DCUIAccess.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to remediate STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## etc Issue
Try{
	$STIGID = "ESXI-80-000191"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH."
  If($controlsenabled.ESXI80000191){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = "Config.Etc.issue"
      $value = $stigsettings.issueBanner
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## SSH Banner
Try{
	$STIGID = "ESXI-80-000192"
	$Title = "The ESXi host SSH daemon must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
  If($controlsenabled.ESXI80000192){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## SSH Disabled
Try{
	$STIGID = "ESXI-80-000193"
	$Title = "The ESXi host must be configured to disable nonessential capabilities by disabling SSH."
  If($controlsenabled.ESXI80000193){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "SSH"
    ForEach($vmhost in $vmhosts){
      $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
      If($vmhostservice.Running -eq $true -or $vmhostservice.Policy -ne "off"){
        If($stigsettings.sshEnabled -eq $false){
          Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
          $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
          $unchangedcount++
        }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
        $unchangedcount++
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

## Shell Disabled
Try{
	$STIGID = "ESXI-80-000194"
	$Title = "The ESXi host must be configured to disable nonessential capabilities by disabling the ESXi shell."
  If($controlsenabled.ESXI80000194){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "ESXi Shell"
    ForEach($vmhost in $vmhosts){
      $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
      If($vmhostservice.Running -eq $true -or $vmhostservice.Policy -ne "off"){
        If($stigsettings.shellEnabled -eq $false){
          Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
          $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
          $unchangedcount++
        }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
        $unchangedcount++
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

## Shell Timeout
Try{
	$STIGID = "ESXI-80-000195"
	$Title = "The ESXi host must automatically stop shell services after ten minutes."
  If($controlsenabled.ESXI80000195){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.shellTimeout.Keys
      $value = [string]$stigsettings.shellTimeout.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## DCUI Timeout
Try{
	$STIGID = "ESXI-80-000196"
	$Title = "The ESXi host must set a timeout to automatically end idle DCUI sessions after ten minutes."
  If($controlsenabled.ESXI80000196){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.DcuiTimeOut.Keys
      $value = [string]$stigsettings.DcuiTimeOut.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Management Separation
Try{
	$STIGID = "ESXI-80-000198"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating ESXi management traffic."
  If($controlsenabled.ESXI80000198){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# Storage Separation
Try{
	$STIGID = "ESXI-80-000199"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
  If($controlsenabled.ESXI80000199){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## Lockdown Exception Users
Try{
	$STIGID = "ESXI-80-000201"
	$Title = "The ESXi host Lockdown Mode exception users list must be verified."
  If($controlsenabled.ESXI80000200){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhostv in $vmhostsv){
      $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
      $exceptions = $lockdown.QueryLockdownExceptions()
      If($exceptions){
        Write-ToConsoleYellow "...Exceptions users $exceptions found for lockdown mode on $($vmhostv.name) .  Please investigate and remove if not documented."
        $changedcount++
      }Else{
        Write-ToConsoleGreen "...No exception users found on $($vmhostv.name)"
        $unchangedcount++
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-ToConsoleRed "Failed to remediate STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# SSH hostbasedauth
Try{
	$STIGID = "ESXI-80-000202"
	$Title = "The ESXi host SSH daemon must not allow host-based authentication."
  If($controlsenabled.ESXI80000202){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH permitemptypasswords
Try{
	$STIGID = "ESXI-80-000203"
	$Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
  If($controlsenabled.ESXI80000203){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH permitemptyuserenv
Try{
	$STIGID = "ESXI-80-000204"
	$Title = "The ESXi host SSH daemon must not permit user environment settings."
  If($controlsenabled.ESXI80000204){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH strictmodes
Try{
	$STIGID = "ESXI-80-000205"
	$Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
  If($controlsenabled.ESXI80000205){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH compression
Try{
	$STIGID = "ESXI-80-000206"
	$Title = "The ESXi host SSH daemon must not allow compression."
  If($controlsenabled.ESXI80000206){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH gatewayports
Try{
	$STIGID = "ESXI-80-000207"
	$Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
  If($controlsenabled.ESXI80000207){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH x11
Try{
	$STIGID = "ESXI-80-000208"
	$Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
  If($controlsenabled.ESXI80000208){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH permit tunnel
Try{
	$STIGID = "ESXI-80-000209"
	$Title = "The ESXi host SSH daemon must not permit tunnels."
  If($controlsenabled.ESXI80000209){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH clientalivecountmax
Try{
	$STIGID = "ESXI-80-000210"
	$Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
  If($controlsenabled.ESXI80000210){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH clientalivecinterval
Try{
	$STIGID = "ESXI-80-000211"
	$Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
  If($controlsenabled.ESXI80000211){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SNMP
Try{
	$STIGID = "ESXI-80-000212"
	$Title = "The ESXi host must disable SNMP v1 and v2c."
  If($controlsenabled.ESXI80000212){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
    #Get/Set-VMhostSnmp only works when connected directly to an ESXi host.
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

# Page Sharing
Try{
	$STIGID = "ESXI-80-000213"
	$Title = "The ESXi host must disable Inter-VM transparent page sharing."
  If($controlsenabled.ESXI80000213){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.ShareForceSalting.Keys
      $value = [string]$stigsettings.ShareForceSalting.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Default Firewall Policy
Try{
	$STIGID = "ESXI-80-000214"
	$Title = "The ESXi host must configure the firewall to block network traffic by default."
  If($controlsenabled.ESXI80000214){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $results = $vmhost | Get-VMHostFirewallDefaultPolicy -ErrorAction Stop
      If($results.IncomingEnabled -eq "True" -xor $results.OutgoingEnabled -eq "True"){
        Write-ToConsoleYellow "...Default firewall policy not configured correctly on $($vmhost.name)...disabling inbound/outbound traffic by default"
        $results | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false -Confirm:$false -ErrorAction Stop
        $changedcount++
      }Else{
        Write-ToConsoleGreen "...Default firewall policy configured correctly on $($vmhost.name)"
        $unchangedcount++
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

# BPDU
Try{
	$STIGID = "ESXI-80-000215"
	$Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
  If($controlsenabled.ESXI80000215){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.BlockGuestBPDU.Keys
      $value = [string]$stigsettings.BlockGuestBPDU.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Forged Transmits
Try{
	$STIGID = "ESXI-80-000216"
	$Title = "The ESXi host must configure virtual switch security policies to reject forged transmits."
  If($controlsenabled.ESXI80000216){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
      If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
        $unchangedcount++
      }Else{
        ForEach($sw in $switches){
          $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.ForgedTransmits -eq $true){
            Write-ToConsoleYellow "...Forged Transmits enabled $($sw.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...Forged Transmits disabled $($sw.name) on $($vmhost.name)"
            $unchangedcount++
          }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
          $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.ForgedTransmits -eq $true -xor $secpol.ForgedTransmitsInherited -eq $false){
            Write-ToConsoleYellow "...Forged Transmits enabled $($pg.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...Forged Transmits disabled $($pg.name) on $($vmhost.name)"
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# MAC Changes
Try{
	$STIGID = "ESXI-80-000217"
	$Title = "The ESXi host must configure virtual switch security policies to reject MAC address changes."
  If($controlsenabled.ESXI80000217){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
      If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
        $unchangedcount++
      }Else{
        ForEach($sw in $switches){
          $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.MacChanges -eq $true){
            Write-ToConsoleYellow "...MAC changes enabled $($sw.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -MacChanges $false -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...MAC changes disabled $($sw.name) on $($vmhost.name)"
            $unchangedcount++
          }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
          $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.MacChanges -eq $true -xor $secpol.MacChangesInherited -eq $false){
            Write-ToConsoleYellow "...MAC changes enabled $($pg.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...MAC changes disabled $($pg.name) on $($vmhost.name)"
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Promiscious Mode
Try{
	$STIGID = "ESXI-80-000218"
	$Title = "The ESXi host must configure virtual switch security policies to reject promiscuous mode requests."
  If($controlsenabled.ESXI80000218){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
      If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
        $unchangedcount++
      }Else{
        ForEach($sw in $switches){
          $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.AllowPromiscuous -eq $true){
            Write-ToConsoleYellow "...Promiscious mode enabled $($sw.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...Promiscious mode disabled $($sw.name) on $($vmhost.name)"
            $unchangedcount++
          }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
          $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
          If($secpol.AllowPromiscuous -eq $true -xor $secpol.AllowPromiscuousInherited -eq $false){
            Write-ToConsoleYellow "...Promiscious mode enabled $($pg.name) on $($vmhost.name)"
            $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false -ErrorAction Stop
            $changedcount++
          }Else{
            Write-ToConsoleGreen "...Promiscious mode disabled $($pg.name) on $($vmhost.name)"
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# DVFilter IP Addresses
Try{
	$STIGID = "ESXI-80-000219"
	$Title = "The ESXi host must restrict use of the dvFilter network API."
  If($controlsenabled.ESXI80000219){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.DVFilterBindIpAddress.Keys
      $value = [string]$stigsettings.DVFilterBindIpAddress.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VLAN Trunk
Try{
	$STIGID = "ESXI-80-000220"
	$Title = "The ESXi host must restrict the use of Virtual Guest Tagging (VGT) on standard switches."
  If($controlsenabled.ESXI80000220){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
      If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for trunked port groups"
        $unchangedcount++
      }Else{
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -eq "4095"}
        If($portgroups.count -eq 0){
          Write-ToConsoleGreen "...No standard port groups found with trunked VLANs on $($vmhost.name)"
          $unchangedcount++
        }Else{
          ForEach($pg in $portgroups){
            Write-ToConsoleRed "...Portgroup $($pg.name) found with VLAN ID set to 4095 on $($vmhost.name).  Investigate and change or document waiver."
            $failedcount++
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

# ESXi Patches
Try{
	$STIGID = "ESXI-80-000221"
	$Title = "The ESXi host must have all security patches and updates installed."
  If($controlsenabled.ESXI80000221){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $build = $vmhost.ExtensionData.Config.Product.build
      If($build -ne $stigsettings.esxiLatestBuild){
        Write-ToConsoleRed "...ESXi is not the latest build $($stigsettings.esxiLatestBuild) on $($vmhost.name)...patch the host with the latest updates!!"
        $failedcount++
      }Else{
        Write-ToConsoleGreen "...ESXi is the latest build $build on $($vmhost.name)"
        $unchangedcount++
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

# Suppress Shell Warning 
Try{
	$STIGID = "ESXI-80-000222"
	$Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
  If($controlsenabled.ESXI80000222){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.suppressShellWarning.Keys
      $value = [string]$stigsettings.suppressShellWarning.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Suppress Hyperthreading Warning
Try{
	$STIGID = "ESXI-80-000223"
	$Title = "The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
  If($controlsenabled.ESXI80000223){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.suppressHyperWarning.Keys
      $value = [string]$stigsettings.suppressHyperWarning.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Syslog Cert Check
Try{
	$STIGID = "ESXI-80-000224"
	$Title = "The ESXi host must verify certificates for SSL syslog endpoints."
  If($controlsenabled.ESXI80000224){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogCertCheck.Keys
      $value = [string]$stigsettings.syslogCertCheck.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## mem eager zero
Try{
	$STIGID = "ESXI-80-000225"
	$Title = "The ESXi host must enable volatile key destruction."
  If($controlsenabled.ESXI80000225){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.memEagerZero.Keys
      $value = [string]$stigsettings.memEagerZero.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## API timeout
Try{
	$STIGID = "ESXI-80-000226"
	$Title = "The ESXi host must configure a session timeout for the vSphere API."
  If($controlsenabled.ESXI80000226){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.apiTimeout.Keys
      $value = [string]$stigsettings.apiTimeout.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Password age
Try{
	$STIGID = "ESXI-80-000227"
	$Title = "The ESXi host must be configured with an appropriate maximum password age."
  If($controlsenabled.ESXI80000227){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.passwordMaxAge.Keys
      $value = [string]$stigsettings.passwordMaxAge.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## CIM Disabled
Try{
	$STIGID = "ESXI-80-000228"
	$Title = "The ESXi CIM service must be disabled."
  If($controlsenabled.ESXI80000228){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "CIM Server"
    ForEach($vmhost in $vmhosts){
      $vmhostservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
      If($vmhostservice.Running -eq $true -or $vmhostservice.Policy -ne "off"){
        If($stigsettings.cimEnabled -eq $false ){
          Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
          $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
          $unchangedcount++
        }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
        $unchangedcount++
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

# Replace Certs
Try{
	$STIGID = "ESXI-80-000229"
	$Title = "The ESXi host must use DoD-approved certificates."
  If($controlsenabled.ESXI80000229){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# SSH allowtcpforwarding
Try{
	$STIGID = "ESXI-80-000230"
	$Title = "The ESXi host SSH daemon must disable port forwarding."
  If($controlsenabled.ESXI80000230){
    Write-ToConsole "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## SLPD Disabled
Try{
	$STIGID = "ESXI-80-000231"
	$Title = "The ESXi host OpenSLP service must be disabled."
  If($controlsenabled.ESXI80000231){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "slpd"
    ForEach($vmhost in $vmhosts){
      $vmhostservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
      If($vmhostservice.Running -eq $true -or $vmhostservice.Policy -ne "off"){
        If($stigsettings.slpdEnabled -eq $false){
          Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
          $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop
          $vmhostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
          $changedcount++
        }Else{
          Write-ToConsoleGreen "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
          $unchangedcount++
        }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
        $unchangedcount++
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

## syslog audit enable
Try{
	$STIGID = "ESXI-80-000232"
	$Title = "The ESXi host must enable audit logging."
  If($controlsenabled.ESXI80000232){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogAuditEnable.Keys
      $value = [boolean]$stigsettings.syslogAuditEnable.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## syslog audit remote
Try{
	$STIGID = "ESXI-80-000233"
	$Title = "The ESXi host must off-load audit records via syslog."
  If($controlsenabled.ESXI80000233){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogAuditRemote.Keys
      $value = [boolean]$stigsettings.syslogAuditRemote.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## syslog cert strict
Try{
	$STIGID = "ESXI-80-000234"
	$Title = "The ESXi host must enable strict x509 verification for SSL syslog endpoints."
  If($controlsenabled.ESXI80000234){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogCertStrict.Keys
      $value = [boolean]$stigsettings.syslogCertStrict.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## syslog log level
Try{
	$STIGID = "ESXI-80-000235"
	$Title = "The ESXi host must forward audit records containing information to establish what type of events occurred."
  If($controlsenabled.ESXI80000235){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogLogLevel.Keys
      $value = [string]$stigsettings.syslogLogLevel.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# VM Override
Try{
	$STIGID = "ESXI-80-000236"
	$Title = "The ESXi host must not be configured to override virtual machine configurations."
  If($controlsenabled.ESXI80000236){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

# VM Override Logs
Try{
	$STIGID = "ESXI-80-000237"
	$Title = "The ESXi host must not be configured to override virtual machine logger settings."
  If($controlsenabled.ESXI80000237){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## TPM Encryption
Try{
	$STIGID = "ESXI-80-000238"
	$Title = "The ESXi host must require TPM-based configuration encryption."
  If($controlsenabled.ESXI80000238){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      $results = $esxcli.system.settings.encryption.get.invoke()
      If($results.Mode -eq "TPM"){
        Write-ToConsoleGreen "...Configuration encryption set correctly to $($results.Mode) on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring configuration encryption on $($vmhost.name)"
        $tpmencarg = $esxcli.system.settings.encryption.set.CreateArgs()
        $tpmencarg.mode = "TPM"
        $esxcli.system.settings.encryption.set.Invoke($tpmencarg)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Firewall Rules
Try{
	$STIGID = "ESXI-80-000239"
	$Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
  If($controlsenabled.ESXI80000239){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      #vSphere Web Client, VMware vCenter Agent, and the Dell VxRail services are excluded from the script due to the order PowerCLI does firewall rules which removes all allowed IPs briefly before setting new allowed ranges which breaks connectivity from vCenter to ESXi so these must be manually done.
      $fwservices = $vmhost | Get-VMHostFirewallException -ErrorAction Stop | Where-Object {($_.Enabled -eq $True) -and ($_.extensiondata.allowedhosts.allip -eq "enabled") -and ($_.Name -ne "vSphere Web Client") -and ($_.Name -ne "dellptagenttcp") -and ($_.Name -ne "dellsshServer") -and ($_.Name -ne "VMware vCenter Agent")}
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      ForEach($fwservice in $fwservices){
        $fwsvcname = $fwservice.extensiondata.key
        Write-ToConsoleYellow "...Configuring ESXi Firewall Policy on service $fwsvcname to $($stigsettings.allowedips) on $vmhost"
        ## Disables All IPs allowed policy
        $fwargs = $esxcli.network.firewall.ruleset.set.CreateArgs()
        $fwargs.allowedall = $false
        $fwargs.rulesetid = $fwsvcname
        $esxcli.network.firewall.ruleset.set.Invoke($fwargs) | Out-Null
        #Add IP ranges to each service
        ForEach($allowedip in $stigsettings.allowedips){
          $fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
          $fwallowedargs.ipaddress = $allowedip
          $fwallowedargs.rulesetid = $fwsvcname
          $esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
          $changedcount++
        }
        #Add 169.254.0.0/16 range to hyperbus service if NSX-T is in use for internal communication
        If($fwsvcname -eq "hyperbus"){
          $fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
          $fwallowedargs.ipaddress = "169.254.0.0/16"
          $fwallowedargs.rulesetid = $fwsvcname
          $esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
          $changedcount++
        }
      }
      If(-not $fwservices){
        Write-ToConsoleGreen "...ESXi Firewall Policy set correctly on $vmhost"
        $unchangedcount++
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

# Active Directory Proxy
Try{
	$STIGID = "ESXI-80-000240"
	$Title = "The ESXi host when using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory."
  If($controlsenabled.ESXI80000240){
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    $skipcount++
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

## ESXi Admins
Try{
	$STIGID = "ESXI-80-000241"
	$Title = "The ESXi host must not use the default Active Directory ESX Admin group."
  If($controlsenabled.ESXI80000241){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.esxAdminsGroup.Keys
      $value = [string]$stigsettings.esxAdminsGroup.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Log Persistent Location
Try{
	$STIGID = "ESXI-80-000243"
	$Title = "The ESXi host must configure a persistent log location for all locally stored logs."
  If($controlsenabled.ESXI80000243){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.syslogScratch.Keys
      $value = $stigsettings.syslogScratch.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Execute Approved VIBs
Try{
	$STIGID = "ESXI-80-000244"
	$Title = "The ESXi host must enforce the exclusive running of executables from approved VIBs."
  If($controlsenabled.ESXI80000244){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $name = $stigsettings.executeVibs.Keys
      $value = [string]$stigsettings.executeVibs.Values
      ## Checking to see if current setting exists
      If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
        If($asetting.value -eq $value){
          Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
          $unchangedcount++
        }Else{
          Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
          $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
          $changedcount++
        }
      }Else{
        Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
        $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Entropy
Try{
	$STIGID = "ESXI-80-000245"
	$Title = "The ESXi host must use sufficient entropy for cryptographic operations."
  If($controlsenabled.ESXI80000245){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      # hwrng
      $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
      If($results -eq "FALSE"){
        Write-ToConsoleGreen "...disableHwrng set correctly to $results on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring disableHwrng on $($vmhost.name)"
        $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $enthwargs.setting = "disableHwrng"
        $enthwargs.value = "FALSE"
        $esxcli.system.settings.kernel.set.invoke($enthwargs)
        $changedcount++
      }
      # sources
      $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "entropySources"} | Select-Object -ExpandProperty Configured
      If($results -eq "0"){
        Write-ToConsoleGreen "...entropySources set correctly to $results on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring entropySources on $($vmhost.name)"
        $entsrcargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $entsrcargs.setting = "entropySources"
        $entsrcargs.value = "0"
        $esxcli.system.settings.kernel.set.invoke($entsrcargs)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

# Log Filtering
Try{
	$STIGID = "ESXI-80-000246"
	$Title = "The ESXi host must not enable log filtering."
  If($controlsenabled.ESXI80000246){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhost in $vmhosts){
      $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
      $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
      If($results -eq $false){
        Write-ToConsoleGreen "...log filtering set correctly to $results on $($vmhost.name)"
        $unchangedcount++
      }Else{
        Write-ToConsoleYellow "...Configuring log filtering on $($vmhost.name)"
        $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
        $lfargs.logfilteringenabled = $false
        $esxcli.system.syslog.config.logfilter.set.invoke($lfargs)
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
  Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
  Write-ToConsoleRed $_.Exception
  $failedcount++
}

## Enable lockdown mode
Try{
	$STIGID = "ESXI-80-000008"
	$Title = "The ESXi host must enable lockdown mode."
  If($controlsenabled.ESXI80000008){
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    ForEach($vmhostv in $vmhostsv){
      If($vmhostv.config.LockdownMode -ne $stigsettings.lockdownlevel){
        Write-ToConsoleYellow "...Enabling Lockdown mode with level $($stigsettings.lockdownlevel) on $($vmhostv.name)"
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
        $lockdown.ChangeLockdownMode($stigsettings.lockdownlevel)
        $changedcount++
      }
      Else{
        Write-ToConsoleGreen "...Lockdown mode already set to $($stigsettings.lockdownlevel) on $($vmhostv.name)"
        $unchangedcount++
      }
    }
  }
  Else{
    Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    $skipcount++
  }
}
Catch{
  Write-ToConsoleRed "Failed to configure STIG ID:$STIGID with Title: $Title on $($vmhostv.name)"
  Write-ToConsoleRed $_.Exception
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
  "controlsenabled" = $controlsenabled
})

$summary = $summary | ConvertTo-Json
Write-ToConsole "...Configuration Summary:"
Write-ToConsole $summary
Write-ToConsole "...Script Complete...Disconnecting from vCenter $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false

#Output run results to file
If($reportpath){
  Stop-Transcript
  ## Results file name for output to json
  $summary | Out-File $resultjson
}
