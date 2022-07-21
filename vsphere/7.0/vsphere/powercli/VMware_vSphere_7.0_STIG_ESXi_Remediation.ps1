<# 
.SYNOPSIS 
    Remediates ESXi hosts against the vSphere ESXi 7.0 STIG Draft.
.DESCRIPTION
    -Remediates a single host or all hosts in a specified cluster.
    -Assumes the VMware DoD STIG VIB is being used to remediate some settings.

.NOTES 
    File Name  : VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.3
    -Powershell 5
    -vCenter/ESXi 7.0 U1/U2

    Example command to run script
    .\VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local -vccred $cred -esxAdminGroup "esxAdmins2" -allowedIPs "10.0.0.0/8" -syslogServer "tcp://log.test.local:514" -ntpServers "time.test.local","time2.test.local"

    .PARAMETER vcenter
    Enter the FQDN or IP of the vCenter Server to connect to
    .PARAMETER vccred
    Enter the pscredential variable name to use for authentication to vCenter. This should be run before the script for example: $cred = get-pscredential 
    .PARAMETER hostname
    Enter the hostname of a single ESXi host to remediate
    .PARAMETER cluster
    Enter the cluster name of a vSphere cluster to remediate all hosts in a targeted cluster
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
$stigsettings = @{
    lockdownlevel           = "lockdownNormal"  #ESXI-70-000001	Lockdown level.  lockdownDisabled,lockdownNormal,lockdownStrict
    DCUIAccess              = @{"DCUI.Access" = "root"}  #ESXI-70-000002
    vibacceptlevel          = "PartnerSupported"  #ESXI-70-000047 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"} #ESXI-70-000005
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} #ESXI-70-000006
    logLevel                = @{"Config.HostAgent.log.level" = "info"} #ESXI-70-000030
    passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-70-000031
    passwordHistory         = @{"Security.PasswordHistory" = "5"} #ESXI-70-000032
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} #ESXI-70-000034
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "120"} #ESXI-70-000041
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"} #ESXI-70-000042
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "120"} #ESXI-70-000043
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"} #ESXI-70-000055
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"} #ESXI-70-000058
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} #ESXI-70-000062
    syslogScratch           = @{"Syslog.global.logDir" = "[] /scratch/log"} #ESXI-70-000045
    sshEnabled              = $false #ESXI-70-000035
    shellEnabled            = $false #ESXI-70-000036
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"} #ESXI-70-000074
    esxiLatestBuild         = "17867351" #ESXI-70-000072
    nativeVLANid            = $nativeVLAN #ESXI-70-000063
    suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} #ESXI-70-000079
    executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"} #ESXI-70-000080
    suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} #ESXI-70-000081
    syslogCertCheck         = @{"Syslog.global.logCheckSSLCerts" = "true"} #ESXI-70-000086
    apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-70-000088
    hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "600"} #ESXI-70-000089
    ##### Environment Specific STIG Values #####
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}   #ESXI-70-000004
    stigVibRE               = "dod-esxi70-stig-re"   #Update with STIG VIB version used
    stigVibRD               = "dod-esxi70-stig-rd"   #Update with STIG VIB version used
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup} #ESXI-70-000039
    allowedips              = $allowedIPs  #ESXI-70-000056 Allows IP ranges for the ESXi firewall
    ntpServers              = $ntpServers #ESXI-70-000046
}

##### Enable or Disable specific STIG Remediations #####
$ESXI70000001 = $true  #Lockdown Mode
$ESXI70000002 = $true  #DCUI.Access List
$ESXI70000003 = $true  #Lockdown Mode Exceptions
$ESXI70000004 = $true  #Syslog
$ESXI70000005 = $true  #Account Lock Failures
$ESXI70000006 = $true  #Account Unlock Timeout
$ESXI70000007 = $true  #Consent Banner Welcome
$ESXI70000008 = $true  #Consent Banner /etc/issue
$ESXI70000009 = $true  #SSH Banner
$ESXI70000010 = $true  #SSH FipsMode
$ESXI70000012 = $true  #SSH IgnoreRhosts yes
$ESXI70000013 = $true  #SSH HostbasedAuthentication no
$ESXI70000014 = $true  #SSH PermitRootLogin no
$ESXI70000015 = $true  #SSH PermitEmptyPasswords no
$ESXI70000016 = $true  #SSH PermitUserEnvironment no
$ESXI70000020 = $true  #SSH StrictModes yes
$ESXI70000021 = $true  #SSH Compression no
$ESXI70000022 = $true  #SSH GatewayPorts no
$ESXI70000023 = $true  #SSH X11Forwarding no
$ESXI70000025 = $true  #SSH PermitTunnel no
$ESXI70000026 = $true  #SSH ClientAliveCountMax 3
$ESXI70000027 = $true  #SSH ClientAliveInterval 200
$ESXI70000030 = $true  #Log Level
$ESXI70000031 = $true  #Password Complexity
$ESXI70000032 = $true  #Password Reuse
$ESXI70000033 = $true  #Password Hashes
$ESXI70000034 = $true  #Mob
$ESXI70000035 = $true  #SSH Running
$ESXI70000036 = $true  #Shell Running
$ESXI70000037 = $true  #Active Directory
$ESXI70000038 = $true  #Authentication Proxy
$ESXI70000039 = $true  #AD Admin Group
$ESXI70000041 = $true  #Shell Interactive Timeout
$ESXI70000042 = $true  #Shell Timeout
$ESXI70000043 = $true  #DCUI Timeout
$ESXI70000045 = $true  #Persistent Logs
$ESXI70000046 = $true  #NTP
$ESXI70000047 = $true  #Acceptance Level
$ESXI70000048 = $true  #Isolate vMotion
$ESXI70000049 = $true  #Protect Management
$ESXI70000050 = $true  #Protect Storage traffic
$ESXI70000053 = $true  #SNMP
$ESXI70000054 = $true  #iSCSI CHAP
$ESXI70000055 = $true  #Memory Salting
$ESXI70000056 = $true  #Firewall Rules
$ESXI70000057 = $true  #Default Firewall
$ESXI70000058 = $true  #BPDU
$ESXI70000059 = $true  #Forged Transmits
$ESXI70000060 = $true  #MAC Changes
$ESXI70000061 = $true  #Prom Mode
$ESXI70000062 = $true  #dvFilter
$ESXI70000063 = $true  #Native VLAN
$ESXI70000064 = $true  #VLAN 4095
$ESXI70000065 = $true  #Reserved VLANs
$ESXI70000070 = $true  #CIM Account
$ESXI70000072 = $true  #Patch Level
$ESXI70000074 = $true  #TLS 1.2
$ESXI70000076 = $true  #Secureboot
$ESXI70000078 = $true  #DoD Cert
$ESXI70000079 = $true  #Suppress Shell Warning
$ESXI70000080 = $true  #execute approved vibs
$ESXI70000081 = $true  #Suppress Hyperthreading Warning
$ESXI70000082 = $true  #SSH AllowTCPForwarding
$ESXI70000083 = $true  #Disable SLPD Service
$ESXI70000086 = $true  #Syslog Cert Verification
$ESXI70000088 = $true  #API Timeout
$ESXI70000089 = $true  #Host Client Timeout
$ESXI70000090 = $true  #Rhttpproxy FIPs
$ESXI70000092 = $true  #VM Override
$ESXI70000093 = $true  #Vm Override Logger

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

#Modules needed to run script and load
$modules = @("VMware.VimAutomation.Core")

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
        Write-Error "Failed to load modules"
        Write-Error $_.Exception
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
    Write-Error "Failed to connect to $vcenter"
    Write-Error $_.Exception
    Exit -1
}

#Gather Info
Try
{
    Write-ToConsole "...Gathering info on target hosts in $vcenter"
    If($hostname){
        $vmhosts = Get-VMHost -Name $hostname | Where-Object {$_.version -match "^7.0*"} | Sort-Object Name
        $vmhostsv = $vmhosts | Get-View | Sort-Object Name
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Found host $vmhost"
        }
    }
    If($cluster){
        $vmhosts = Get-Cluster -Name $cluster | Get-VMHost | Where-Object {$_.version -match "^7.0*"} | Sort-Object Name
        $vmhostsv = $vmhosts | Get-View | Sort-Object Name
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Found host $vmhost"
        }
    } 
}
Catch
{
    Write-Error "Failed to gather information on target hosts in $vcenter"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## DCUI.Access
Try{
	$VULID = "V-239259"
	$STIGID = "ESXI-70-000002"
	$Title = "The ESXi host must verify the DCUI.Access list."
    If($ESXI70000002){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.DCUIAccess.Keys
            $value = $stigsettings.DCUIAccess.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Lockdown Exception Users
Try{
	$VULID = "V-239260"
	$STIGID = "ESXI-70-000003"
	$Title = "The ESXi host must verify the exception users list for lockdown mode."
    If($ESXI70000003){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhostv in $vmhostsv){
            $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager
            $exceptions = $lockdown.QueryLockdownExceptions()
            If($exceptions){
                Write-ToConsoleRed "...Exceptions users $exceptions found for lockdown mode on $($vmhostv.name) .  Please investigate and remove if not documented."
            }Else{
                Write-ToConsoleGreen "...No exception users found on $($vmhostv.name)"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhostv.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Syslog
Try{
	$VULID = "V-239261"
	$STIGID = "ESXI-70-000004"
	$Title = "Remote logging for ESXi hosts must be configured."
    If($ESXI70000004){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        If($logInsight){
            Write-ToConsole "...Log Insight used to manage syslog skipping this control"
        }Else{
            ForEach($vmhost in $vmhosts){
                $name = $stigsettings.syslogHost.Keys
                $value = [string]$stigsettings.syslogHost.Values
                ## Checking to see if current setting exists
                If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                    If($asetting.value -eq $value){
                    Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                    }Else{
                        Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                    }
                }Else{
                    Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                    $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
                }
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Account Lock Failures
Try{
	$VULID = "V-239262"
	$STIGID = "ESXI-70-000005"
	$Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
    If($ESXI70000005){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.accountLockFailures.Keys
            $value = [string]$stigsettings.accountLockFailures.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Account Unlock Timeout
Try{
	$VULID = "V-239263"
	$STIGID = "ESXI-70-000006"
	$Title = "The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out."
    If($ESXI70000006){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.accountUnlockTime.Keys
            $value = [string]$stigsettings.accountUnlockTime.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Welcome banner
Try{
	$VULID = "V-239264"
	$STIGID = "ESXI-70-000007"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    If($ESXI70000007){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## /etc/issue Banner
Try{
	$VULID = "V-239265"
	$STIGID = "ESXI-70-000008"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    If($ESXI70000008){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH Banner
Try{
	$VULID = "V-239266"
	$STIGID = "ESXI-70-000009"
	$Title = "The ESXi host SSH daemon must be configured with the DoD logon banner."
    If($ESXI70000009){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH Ciphers
Try{
	$VULID = "V-239267"
	$STIGID = "ESXI-70-000010"
	$Title = "The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions."
    If($ESXI70000010){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.security.fips140.ssh.get.invoke()
            If($results -ne "true"){
                Write-ToConsoleGreen "...SSH FipsMode set correctly to $results on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...Configuring SSH FipsMode on $($vmhost.name)"
                $fipsargs = $esxcli.system.security.fips140.ssh.set.CreateArgs()
                $fipsargs.enable = $true
                $esxcli.system.security.fips140.ssh.set.Invoke($fipsargs)
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH .rhosts
Try{
	$VULID = "V-239268"
	$STIGID = "ESXI-70-000012"
	$Title = "The ESXi host SSH daemon must ignore .rhosts files."
    If($ESXI70000012){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH hostbasedauth
Try{
	$VULID = "V-239269"
	$STIGID = "ESXI-70-000013"
	$Title = "The ESXi host SSH daemon must not allow host-based authentication."
    If($ESXI70000013){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH PermitRootLogin
Try{
	$VULID = "V-239270"
	$STIGID = "ESXI-70-000014"
	$Title = "The ESXi host SSH daemon must not permit root logins."
    If($ESXI70000014){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                If($results.Name -eq $stigsettings.stigVibRE){
                    Write-ToConsoleRed "...VMware STIG VIB Root Enabled is installed on $($vmhost.name). !!Ensure this is waivered!!"
                }Else{
                    Write-ToConsoleGreen "...VMware STIG VIB Root Disabled is installed on $($vmhost.name)"
                }
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH PermitEmptyPasswords
Try{
	$VULID = "V-239271"
	$STIGID = "ESXI-70-000015"
	$Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
    If($ESXI70000015){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH PermitUserEnvironment
Try{
	$VULID = "V-239272"
	$STIGID = "ESXI-70-000016"
	$Title = "The ESXi host SSH daemon must not permit user environment settings."
    If($ESXI70000016){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH StrictMode
Try{
	$VULID = "V-239275"
	$STIGID = "ESXI-70-000020"
	$Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
    If($ESXI70000020){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH Compression
Try{
	$VULID = "V-239276"
	$STIGID = "ESXI-70-000021"
	$Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
    If($ESXI70000021){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH Gateway Ports
Try{
	$VULID = "V-239277"
	$STIGID = "ESXI-70-000022"
	$Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
    If($ESXI70000022){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH X11
Try{
	$VULID = "V-239278"
	$STIGID = "ESXI-70-000023"
	$Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
    If($ESXI70000023){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH PermitTunnel
Try{
	$VULID = "V-239280"
	$STIGID = "ESXI-70-000025"
	$Title = "The ESXi host SSH daemon must not permit tunnels."
    If($ESXI70000025){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH ClientAliveCount
Try{
	$VULID = "V-239281"
	$STIGID = "ESXI-70-000026"
	$Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
    If($ESXI70000026){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH ClientAliveInterval
Try{
	$VULID = "V-239282"
	$STIGID = "ESXI-70-000027"
	$Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
    If($ESXI70000027){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Log Level
Try{
	$VULID = "V-239285"
	$STIGID = "ESXI-70-000030"
	$Title = "The ESXi host must produce audit records containing information to establish what type of events occurred."
    If($ESXI70000030){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.logLevel.Keys
            $value = [string]$stigsettings.logLevel.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Password Complexity
Try{
	$VULID = "V-239286"
	$STIGID = "ESXI-70-000031"
	$Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
    If($ESXI70000031){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.passwordComplexity.Keys
            $value = [string]$stigsettings.passwordComplexity.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Password Reuse
Try{
	$VULID = "V-239287"
	$STIGID = "ESXI-70-000032"
	$Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
    If($ESXI70000032){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.passwordHistory.Keys
            $value = [string]$stigsettings.passwordHistory.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Password Hashes
Try{
	$VULID = "V-239288"
	$STIGID = "ESXI-70-000033"
	$Title = "The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm."
    If($ESXI70000033){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
Write-Error $_.Exception
Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
Exit -1
}

## MOB
Try{
	$VULID = "V-239289"
	$STIGID = "ESXI-70-000034"
	$Title = "The ESXi host must disable the Managed Object Browser (MOB)."
    If($ESXI70000034){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.enableMob.Keys
            $value = [boolean]$stigsettings.enableMob.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SSH Disabled
Try{
	$VULID = "V-239290"
	$STIGID = "ESXI-70-000035"
	$Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
    If($ESXI70000035){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $servicename = "SSH"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename}
            If($vmhostservice.Running -eq $true){
                If($stigsettings.sshEnabled -eq $false){
                    Write-ToConsoleRed "...Stopping service $servicename on $($vmhost.name)"
                    $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false
                    $vmhostservice | Stop-VMHostService -Confirm:$false
                }Else{
                    Write-ToConsoleRed "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
                }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
			} 
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Shell Disabled
Try{
	$VULID = "V-239291"
	$STIGID = "ESXI-70-000036"
	$Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
    If($ESXI70000036){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $servicename = "ESXi Shell"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename}
            If($vmhostservice.Running -eq $true){
                If($stigsettings.shellEnabled -eq $false){
                    Write-ToConsoleRed "...Stopping service $servicename on $($vmhost.name)"
                    $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false
                    $vmhostservice | Stop-VMHostService -Confirm:$false
                }Else{
                    Write-ToConsoleRed "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
                }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
			} 
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Active Directory
Try{
	$VULID = "V-239292"
	$STIGID = "ESXI-70-000037"
	$Title = "The ESXi host must use Active Directory for local user authentication."
    If($ESXI70000037){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Active Directory
Try{
	$VULID = "V-239293"
	$STIGID = "ESXI-70-000038"
	$Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
    If($ESXI70000038){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXi Admins
Try{
	$VULID = "V-239294"
	$STIGID = "ESXI-70-000039"
	$Title = "Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory."
    If($ESXI70000039){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.esxAdminsGroup.Keys
            $value = [string]$stigsettings.esxAdminsGroup.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Shell Interactive Timeout
Try{
	$VULID = "V-239296"
	$STIGID = "ESXI-70-000041"
	$Title = "The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes."
    If($ESXI70000041){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.shellIntTimeout.Keys
            $value = [string]$stigsettings.shellIntTimeout.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Shell Timeout
Try{
	$VULID = "V-239297"
	$STIGID = "ESXI-70-000042"
	$Title = "The ESXi host must terminate shell services after 10 minutes."
    If($ESXI70000042){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.shellTimeout.Keys
            $value = [string]$stigsettings.shellTimeout.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## DCUI Timeout
Try{
	$VULID = "V-239298"
	$STIGID = "ESXI-70-000043"
	$Title = "The ESXi host must log out of the console UI after two minutes."
    If($ESXI70000043){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.DcuiTimeOut.Keys
            $value = [string]$stigsettings.DcuiTimeOut.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Log Persistent Location
Try{
	$VULID = "V-239300"
	$STIGID = "ESXI-70-000045"
	$Title = "The ESXi host must enable a persistent log location for all locally stored logs."
    If($ESXI70000045){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.syslogScratch.Keys
            $value = $stigsettings.syslogScratch.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# NTP
Try{
	$VULID = "V-239301"
	$STIGID = "ESXI-70-000046"
	$Title = "The ESXi host must configure NTP time synchronization."
    If($ESXI70000046){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $currentntp = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
            If($currentntp.count -eq "0"){
                Write-ToConsoleRed "...No NTP servers configured on $($vmhost.name)...configuring NTP"
                $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers
                $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
                $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
            }
            else{
                If($stigsettings.ntpServers[0] -ne $currentntp[0] -or $stigsettings.ntpServers[1] -ne $currentntp[1]){
                    Write-ToConsoleRed "...NTP Servers configured incorrectly on $($vmhost.name)...reconfiguring NTP"
                    ForEach($ntp in $currentntp){
                        $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false
                    }
                    $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers
                    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
                    $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
                }Else{
                    Write-ToConsoleGreen "...NTP Servers configured Correctly on $($vmhost.name)"
                }
            }
    	}
	}
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# VIB Acceptance
Try{
	$VULID = "V-239302"
	$STIGID = "ESXI-70-000047"
	$Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) Acceptance Levels must be verified."
    If($ESXI70000047){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.acceptance.get.Invoke()
            If($results -ne "CommunitySupported"){
                Write-ToConsoleGreen "...VIB Acceptance level is set correctly to $results on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...Configuring VIB Acceptance level back to the default of PartnerSupported on $($vmhost.name)"
                $vibargs = $esxcli.software.acceptance.set.CreateArgs()
                $vibargs.level = "PartnerSupported"
                $esxcli.software.acceptance.set.Invoke($vibargs)
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# vMotion Separation
Try{
	$VULID = "V-239303"
	$STIGID = "ESXI-70-000048"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
    If($ESXI70000048){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel
            ForEach($vmk in $vmks){
                If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
                    Write-ToConsoleRed "...VMKernel $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name).  Investigate and separate functions to another network and VMKernel."
                }ElseIf($vmk.VMotionEnabled -eq "True"){
                    Write-ToConsoleGreen "...VMKernel $($vmk.name) appears to have vMotion only enabled on $($vmhost.name)"
                }
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Management Separation
Try{
	$VULID = "V-239304"
	$STIGID = "ESXI-70-000049"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
    If($ESXI70000049){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Storage Separation
Try{
	$VULID = "V-239305"
	$STIGID = "ESXI-70-000050"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
    If($ESXI70000050){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SNMP
Try{
	$VULID = "V-239307"
	$STIGID = "ESXI-70-000053"
	$Title = "SNMP must be configured properly on the ESXi host."
    If($ESXI70000053){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        #Get/Set-VMhostSnmp only works when connected directly to an ESXi host.
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# iSCSI CHAP
Try{
	$VULID = "V-239308"
	$STIGID = "ESXI-70-000054"
	$Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
    If($ESXI70000054){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Page Sharing
Try{
	$VULID = "V-239309"
	$STIGID = "ESXI-70-000055"
	$Title = "The ESXi host must disable Inter-VM transparent page sharing."
    If($ESXI70000055){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.ShareForceSalting.Keys
            $value = [string]$stigsettings.ShareForceSalting.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Firewall Rules
Try{
	$VULID = "V-239310"
	$STIGID = "ESXI-70-000056"
	$Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
    If($ESXI70000056){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            #vSphere Web Client, VMware vCenter Agent, and the Dell VxRail services are excluded from the script due to the order PowerCLI does firewall rules which removes all allowed IPs briefly before setting new allowed ranges which breaks connectivity from vCenter to ESXi so these must be manually done.
            $fwservices = $vmhost | Get-VMHostFirewallException | Where-Object {($_.Enabled -eq $True) -and ($_.extensiondata.allowedhosts.allip -eq "enabled") -and ($_.Name -ne "vSphere Web Client") -and ($_.Name -ne "dellptagenttcp") -and ($_.Name -ne "dellsshServer") -and ($_.Name -ne "VMware vCenter Agent")}
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            ForEach($fwservice in $fwservices){
                $fwsvcname = $fwservice.extensiondata.key
                Write-ToConsoleRed "...Configuring ESXi Firewall Policy on service $fwsvcname to $($stigsettings.allowedips) on $vmhost"
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
                }
                #Add 169.254.0.0/16 range to hyperbus service if NSX-T is in use for internal communication
                If($fwsvcname -eq "hyperbus"){
                    $fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
                    $fwallowedargs.ipaddress = "169.254.0.0/16"
                    $fwallowedargs.rulesetid = $fwsvcname
                    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
                }
            }
            If(-not $fwservices){
                Write-ToConsoleGreen "...ESXi Firewall Policy set correctly on $vmhost"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Default Firewall Policy
Try{
	$VULID = "V-239311"
	$STIGID = "ESXI-70-000057"
	$Title = "The ESXi host must configure the firewall to block network traffic by default."
    If($ESXI70000057){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $results = $vmhost | Get-VMHostFirewallDefaultPolicy
            If($results.IncomingEnabled -eq "True" -xor $results.OutgoingEnabled -eq "True"){
                Write-ToConsoleRed "...Default firewall policy not configured correctly on $($vmhost.name)...disabling inbound/outbound traffic by default"
                $results | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false -Confirm:$false
            }Else{
                Write-ToConsoleGreen "...Default firewall policy configured correctly on $($vmhost.name)"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Page Sharing
Try{
	$VULID = "V-239312"
	$STIGID = "ESXI-70-000058"
	$Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
    If($ESXI70000058){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.BlockGuestBPDU.Keys
            $value = [string]$stigsettings.BlockGuestBPDU.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Forged Transmits
Try{
	$VULID = "V-239313"
	$STIGID = "ESXI-70-000059"
	$Title = "The virtual switch Forged Transmits policy must be set to reject on the ESXi host."
    If($ESXI70000059){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.ForgedTransmits -eq $true){
                        Write-ToConsoleRed "...Forged Transmits enabled $($sw.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...Forged Transmits disabled $($sw.name) on $($vmhost.name)"
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.ForgedTransmits -eq $true -xor $secpol.ForgedTransmitsInherited -eq $false){
                        Write-ToConsoleRed "...Forged Transmits enabled $($pg.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...Forged Transmits disabled $($pg.name) on $($vmhost.name)"
                    }
                }
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# MAC Changes
Try{
	$VULID = "V-239314"
	$STIGID = "ESXI-70-000060"
	$Title = "The virtual switch MAC Address Change policy must be set to reject on the ESXi host."
    If($ESXI70000060){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.MacChanges -eq $true){
                        Write-ToConsoleRed "...MAC changes enabled $($sw.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -MacChanges $false -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...MAC changes disabled $($sw.name) on $($vmhost.name)"
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.MacChanges -eq $true -xor $secpol.MacChangesInherited -eq $false){
                        Write-ToConsoleRed "...MAC changes enabled $($pg.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...MAC changes disabled $($pg.name) on $($vmhost.name)"
                    }
                }
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Promiscious Mode
Try{
	$VULID = "V-239315"
	$STIGID = "ESXI-70-000061"
	$Title = "The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host."
    If($ESXI70000061){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.AllowPromiscuous -eq $true){
                        Write-ToConsoleRed "...Promiscious mode enabled $($sw.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...Promiscious mode disabled $($sw.name) on $($vmhost.name)"
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.AllowPromiscuous -eq $true -xor $secpol.AllowPromiscuousInherited -eq $false){
                        Write-ToConsoleRed "...Promiscious mode enabled $($pg.name) on $($vmhost.name)"
                        $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false
                    }Else{
                        Write-ToConsoleGreen "...Promiscious mode disabled $($pg.name) on $($vmhost.name)"
                    }
                }
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# DVFilter IP Addresses
Try{
	$VULID = "V-239316"
	$STIGID = "ESXI-70-000062"
	$Title = "The ESXi host must prevent unintended use of the dvFilter network APIs."
    If($ESXI70000062){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.DVFilterBindIpAddress.Keys
            $value = [string]$stigsettings.DVFilterBindIpAddress.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# VLAN IDs
Try{
	$VULID = "V-239317"
	$STIGID = "ESXI-70-000063"
	$Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
    If($ESXI70000063){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for native VLAN Id: $($stigsettings.nativeVLANid)"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where-Object {$_.VlanId -eq $stigsettings.nativeVLANid}
                If($portgroups.count -eq 0){
                    Write-ToConsoleGreen "...No port groups found with native VLAN Id $($stigsettings.nativeVLANid) on $($vmhost.name)"
                }Else{
                    ForEach($pg in $portgroups){
                        Write-ToConsoleRed "...Portgroup $($pg.name) found with native VLAN Id: $($stigsettings.nativeVLANid) on $($vmhost.name).  Investigate and change or document waiver."
                    }
                } 
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# VLAN Trunk
Try{
	$VULID = "V-239318"
	$STIGID = "ESXI-70-000064"
	$Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
    If($ESXI70000064){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for trunked port groups"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where-Object {$_.VlanId -eq "4095"}
                If($portgroups.count -eq 0){
                    Write-ToConsoleGreen "...No standard port groups found with trunked VLANs on $($vmhost.name)"
                }Else{
                    ForEach($pg in $portgroups){
                        Write-ToConsoleRed "...Portgroup $($pg.name) found with VLAN ID set to 4095 on $($vmhost.name).  Investigate and change or document waiver."
                    }
                } 
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Reserved VLANs
Try{
	$VULID = "V-239319"
	$STIGID = "ESXI-70-000065"
	$Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
    If($ESXI70000065){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for reserved VLAN IDs on port groups"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where-Object {$_.VlanId -In 1001..1024 -or $_.VlanId -In 3968...4047 -or $_.VlanId -In 4094}
                If($portgroups.count -eq 0){
                    Write-ToConsoleGreen "...No standard port groups found with reserved VLAN IDs on $($vmhost.name)"
                }Else{
                    ForEach($pg in $portgroups){
                        Write-ToConsoleRed "...Portgroup $($pg.name) found with reserved VLAN ID: $($pg.VlanId) on $($vmhost.name).  Investigate and change or document waiver."
                    }
                } 
            }            
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# CIM User
Try{
	$VULID = "V-239323"
	$STIGID = "ESXI-70-000070"
	$Title = "The ESXi host must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications."
    If($ESXI70000070){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXi Patches
Try{
	$VULID = "V-239325"
	$STIGID = "ESXI-70-000072"
	$Title = "The ESXi host must have all security patches and updates installed."
    If($ESXI70000072){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $build = $vmhost.ExtensionData.Config.Product.build
            If($build -ne $stigsettings.esxiLatestBuild){
                Write-ToConsoleRed "...ESXi is not the latest build $($stigsettings.esxiLatestBuild) on $($vmhost.name)...patch the host with the latest updates!!"
            }Else{
                Write-ToConsoleGreen "...ESXi is the latest build $build on $($vmhost.name)"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# TLS 1.2 
Try{
	$VULID = "V-239326"
	$STIGID = "ESXI-70-000074"
	$Title = "The ESXi host must exclusively enable TLS 1.2 for all endpoints."
    If($ESXI70000074){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.sslProtocols.Keys
            $value = [string]$stigsettings.sslProtocols.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Secure Boot
Try{
	$VULID = "V-239327"
	$STIGID = "ESXI-70-000076"
	$Title = "The ESXi host must enable Secure Boot."
    If($ESXI70000076){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Replace Certs
Try{
	$VULID = "V-239328"
	$STIGID = "ESXI-70-000078"
	$Title = "The ESXi host must use DoD-approved certificates."
    If($ESXI70000078){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# Suppress Shell Warning 
Try{
	$VULID = "V-239329"
	$STIGID = "ESXI-70-000079"
	$Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
    If($ESXI70000079){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.suppressShellWarning.Keys
            $value = [string]$stigsettings.suppressShellWarning.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Execute Approved VIBs
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000080"
	$Title = "The ESXi host must only run executables from approved VIBs."
    If($ESXI70000080){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.executeVibs.Keys
            $value = [string]$stigsettings.executeVibs.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Suppress Hyperthreading Warning
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000081"
	$Title = "The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
    If($ESXI70000081){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.suppressHyperWarning.Keys
            $value = [string]$stigsettings.suppressHyperWarning.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# SSH allowtcpforwardning
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000082"
	$Title = "The ESXi host SSH daemon must disable port forwarding."
    If($ESXI70000082){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## SLPD Disabled
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000083"
	$Title = "The ESXi host OpenSLP service must be disabled."
    If($ESXI70000083){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $servicename = "slpd"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename}
            If($vmhostservice.Running -eq $true){
                If($stigsettings.sshEnabled -eq $false){
                    Write-ToConsoleRed "...Stopping service $servicename on $($vmhost.name)"
                    $vmhostservice | Set-VMHostService -Policy Off -Confirm:$false
                    $vmhostservice | Stop-VMHostService -Confirm:$false
                }Else{
                    Write-ToConsoleRed "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
                }
			}Else{
				Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
			} 
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Syslog Cert Check
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000086"
	$Title = "The ESXi host must verify certificates for SSL syslog endpoints."
    If($ESXI70000086){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.syslogCertCheck.Keys
            $value = [string]$stigsettings.syslogCertCheck.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## API timeout
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000088"
	$Title = "The ESXi host must configure a session timeout for the vSphere API."
    If($ESXI70000088){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.apiTimeout.Keys
            $value = [string]$stigsettings.apiTimeout.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Host Client timeout
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000089"
	$Title = "The ESXi Host Client must be configured with a session timeout."
    If($ESXI70000089){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.hostClientTimeout.Keys
            $value = [string]$stigsettings.hostClientTimeout.Values
            ## Checking to see if current setting exists
            If($asetting = $vmhost | Get-AdvancedSetting -Name $name){
                If($asetting.value -eq $value){
                Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
                }Else{
                    Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                }
            }Else{
                Write-ToConsole "...Setting $name does not exist on $vmhost...creating setting..."
                $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Rhttpproxy FIPs
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000090"
	$Title = "The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
    If($ESXI70000090){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.security.fips140.rhttpproxy.get.invoke()
            If($results -ne "true"){
                Write-ToConsoleGreen "...SSH FipsMode set correctly to $results on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...Configuring SSH FipsMode on $($vmhost.name)"
                $fipsargs = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
                $fipsargs.enable = $true
                $esxcli.system.security.fips140.rhttpproxy.set.Invoke($fipsargs)
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# VM Override
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000092"
	$Title = "The ESXi host must not be configured to override virtual machine configurations."
    If($ESXI70000092){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# VM Override Logs
Try{
	$VULID = "N/A"
	$STIGID = "ESXI-70-000093"
	$Title = "The ESXi host must not be configured to override virtual machine logger settings."
    If($ESXI70000093){
        Write-ToConsole "...!!This control must be remediated manually!! Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Enable lockdown mode
Try{
	$VULID = "V-239258"
	$STIGID = "ESXI-70-000001"
	$Title = "Access to the ESXi host must be limited by enabling Lockdown Mode."
    If($ESXI70000001){
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhostv in $vmhostsv){
            If($vmhostv.config.LockdownMode -ne $stigsettings.lockdownlevel){
                Write-ToConsole "...Enabling Lockdown mode with level $($stigsettings.lockdownlevel) on $($vmhostv.name)"
                $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager
                $lockdown.ChangeLockdownMode($stigsettings.lockdownlevel) 
            }
            Else{
                Write-ToConsoleGreen "...Lockdown mode already set to $($stigsettings.lockdownlevel) on $($vmhostv.name)"    
            }
        }
    }
    Else{
        Write-ToConsole "...Skipping disabled control Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to configure Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhostv.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

Write-ToConsole "...Script Complete...Disconnecting from vCenter $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false