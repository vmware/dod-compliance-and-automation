<# 
.SYNOPSIS 
    Remediates ESXi hosts against the vSphere ESXi 6.7 STIG Version 1 Release 1.
.DESCRIPTION
    -Remediates a single host or all hosts in a specified cluster.
    -Assumes the VMware DoD STIG VIB is being used to remediate some settings.

.NOTES 
    File Name  : VMware_vSphere_6.7_STIG_ESXi_Remediation.ps1 
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.3
    -Powershell 5
    -vCenter/ESXi 6.7 U3+

    Example command to run script
    .\VMware_vSphere_6.7_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local -vccred $cred -esxAdminGroup "esxAdmins2" -allowedIPs "10.0.0.0/8" -syslogServer "tcp://log.test.local:514" -ntpServers "time.test.local","time2.test.local"

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
    [Parameter(Mandatory=$false)]
    [string]$hostname,
    [Parameter(Mandatory=$false)]
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
    lockdownlevel           = "lockdownNormal"  #ESXI-67-000001	Lockdown level.  lockdownDisabled,lockdownNormal,lockdownStrict
    DCUIAccess              = @{"DCUI.Access" = "root"}  #ESXI-67-000002
    vibacceptlevel          = "PartnerSupported"  #ESXI-67-000047 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"} #ESXI-67-000005
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} #ESXI-67-000006
    logLevel                = @{"Config.HostAgent.log.level" = "info"} #ESXI-67-000030
    passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-67-000031
    passwordHistory         = @{"Security.PasswordHistory" = "5"} #ESXI-67-000032
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} #ESXI-67-000034
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "120"} #ESXI-67-000041
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"} #ESXI-67-000042
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "120"} #ESXI-67-000043
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"} #ESXI-67-000055
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"} #ESXI-67-000058
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} #ESXI-67-000062
    syslogScratch           = @{"Syslog.global.logDir" = "[] /scratch/log"} #ESXI-67-000045
    sshEnabled              = $false #ESXI-67-000035
    shellEnabled            = $false #ESXI-67-000036
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"} #ESXI-67-000074
    esxiLatestBuild         = "17700523" #ESXI-67-000072
    nativeVLANid            = $nativeVLAN #ESXI-67-000063
    suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} #ESXI-67-000079
    ##### Environment Specific STIG Values #####
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}   #ESXI-67-000004
    stigVibRE               = "dod-esxi67-stig-re"   #Update with STIG VIB version used
    stigVibRD               = "dod-esxi67-stig-rd"   #Update with STIG VIB version used
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup} #ESXI-67-000039
    allowedips              = $allowedIPs  #ESXI-67-000056 Allows IP ranges for the ESXi firewall
    ntpServers              = $ntpServers #ESXI-67-000046
}

##### Enable or Disable specific STIG Remediations #####
$ESXI67000001 = $true  #Lockdown Mode
$ESXI67000002 = $true  #DCUI.Access List
$ESXI67000003 = $true  #Lockdown Mode Exceptions
$ESXI67000004 = $true  #Syslog
$ESXI67000005 = $true  #Account Lock Failures
$ESXI67000006 = $true  #Account Unlock Timeout
$ESXI67000007 = $true  #Consent Banner Welcome
$ESXI67000008 = $true  #Consent Banner /etc/issue
$ESXI67000009 = $true  #SSH Banner
$ESXI67000010 = $true  #SSH FipsMode
$ESXI67000012 = $true  #SSH IgnoreRhosts yes
$ESXI67000013 = $true  #SSH HostbasedAuthentication no
$ESXI67000014 = $true  #SSH PermitRootLogin no
$ESXI67000015 = $true  #SSH PermitEmptyPasswords no
$ESXI67000016 = $true  #SSH PermitUserEnvironment no
$ESXI67000018 = $true  #SSH GSSAPIAuthentication no
$ESXI67000019 = $true  #SSH KerberosAuthentication no
$ESXI67000020 = $true  #SSH StrictModes yes
$ESXI67000021 = $true  #SSH Compression no
$ESXI67000022 = $true  #SSH GatewayPorts no
$ESXI67000023 = $true  #SSH X11Forwarding no
$ESXI67000024 = $true  #SSH AcceptEnv
$ESXI67000025 = $true  #SSH PermitTunnel no
$ESXI67000026 = $true  #SSH ClientAliveCountMax 3
$ESXI67000027 = $true  #SSH ClientAliveInterval 200
$ESXI67000028 = $true  #SSH MaxSessions 1
$ESXI67000029 = $true  #Authorized Keys
$ESXI67000030 = $true  #Log Level
$ESXI67000031 = $true  #Password Complexity
$ESXI67000032 = $true  #Password Reuse
$ESXI67000033 = $true  #Password Hashes
$ESXI67000034 = $true  #Mob
$ESXI67000035 = $true  #SSH Running
$ESXI67000036 = $true  #Shell Running
$ESXI67000037 = $true  #Active Directory
$ESXI67000038 = $true  #Authentication Proxy
$ESXI67000039 = $true  #AD Admin Group
$ESXI67000040 = $true  #DCUI Smartcard
$ESXI67000041 = $true  #Shell Interactive Timeout
$ESXI67000042 = $true  #Shell Timeout
$ESXI67000043 = $true  #DCUI Timeout
$ESXI67000044 = $true  #Core Dumps
$ESXI67000045 = $true  #Persistent Logs
$ESXI67000046 = $true  #NTP
$ESXI67000047 = $true  #Acceptance Level
$ESXI67000048 = $true  #Isolate vMotion
$ESXI67000049 = $true  #Protect Management
$ESXI67000050 = $true  #Protect Storage traffic
$ESXI67000052 = $true   #TCP/IP Stacks
$ESXI67000053 = $true  #SNMP
$ESXI67000054 = $true  #iSCSI CHAP
$ESXI67000055 = $true  #Memory Salting
$ESXI67000056 = $true  #Firewall Rules
$ESXI67000057 = $true  #Default Firewall
$ESXI67000058 = $true  #BPDU
$ESXI67000059 = $true  #Forged Transmits
$ESXI67000060 = $true  #MAC Changes
$ESXI67000061 = $true  #Prom Mode
$ESXI67000062 = $true  #dvFilter
$ESXI67000063 = $true  #Native VLAN
$ESXI67000064 = $true  #VLAN 4095
$ESXI67000065 = $true  #Reserved VLANs
$ESXI67000066 = $true  #DTP
$ESXI67000067 = $true  #STP
$ESXI67000068 = $true  #Required VLANs
$ESXI67000070 = $true  #CIM Account
$ESXI67000071 = $true  #Checksum
$ESXI67000072 = $true  #Patch Level
$ESXI67000074 = $true  #TLS 1.2
$ESXI67000076 = $true  #Secureboot
$ESXI67000078 = $true  #DoD Cert
$ESXI67000079 = $true  #Suppress Shell Warning

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
        $vmhosts = Get-VMHost -Name $hostname | Where-Object {$_.version -match "^6.7*"} | Sort-Object Name
        $vmhostsv = $vmhosts | Get-View | Sort-Object Name
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Found host $vmhost"
        }
    }
    If($cluster){
        $vmhosts = Get-Cluster -Name $cluster | Get-VMHost | Where-Object {$_.version -match "^6.7*"} | Sort-Object Name
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
    If($ESXI67000002){
        $VULID = "V-239259"
        $STIGID = "ESXI-67-000002"
        $Title = "The ESXi host must verify the DCUI.Access list."
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
    If($ESXI67000003){
        $VULID = "V-239260"
        $STIGID = "ESXI-67-000003"
        $Title = "The ESXi host must verify the exception users list for lockdown mode."
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
    If($ESXI67000004){
        $VULID = "V-239261"
        $STIGID = "ESXI-67-000004"
        $Title = "Remote logging for ESXi hosts must be configured."
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
    If($ESXI67000005){
        $VULID = "V-239262"
        $STIGID = "ESXI-67-000005"
        $Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
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
    If($ESXI67000006){
        $VULID = "V-239263"
        $STIGID = "ESXI-67-000006"
        $Title = "The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out."
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
    If($ESXI67000007){
        $VULID = "V-239264"
        $STIGID = "ESXI-67-000007"
        $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
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
    If($ESXI67000008){
        $VULID = "V-239265"
        $STIGID = "ESXI-67-000008"
        $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
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
    If($ESXI67000009){
        $VULID = "V-239266"
        $STIGID = "ESXI-67-000009"
        $Title = "The ESXi host SSH daemon must be configured with the DoD logon banner."
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
    If($ESXI67000010){
        $VULID = "V-239267"
        $STIGID = "ESXI-67-000010"
        $Title = "The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions."
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
    If($ESXI67000012){
        $VULID = "V-239268"
        $STIGID = "ESXI-67-000012"
        $Title = "The ESXi host SSH daemon must ignore .rhosts files."
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
    If($ESXI67000013){
        $VULID = "V-239269"
        $STIGID = "ESXI-67-000013"
        $Title = "The ESXi host SSH daemon must not allow host-based authentication."
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
    If($ESXI67000014){
        $VULID = "V-239270"
        $STIGID = "ESXI-67-000014"
        $Title = "The ESXi host SSH daemon must not permit root logins."
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
    If($ESXI67000015){
        $VULID = "V-239271"
        $STIGID = "ESXI-67-000015"
        $Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
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
    If($ESXI67000016){
        $VULID = "V-239272"
        $STIGID = "ESXI-67-000016"
        $Title = "The ESXi host SSH daemon must not permit user environment settings."
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

# SSH GSSAPI
Try{
    If($ESXI67000018){
        $VULID = "V-239273"
        $STIGID = "ESXI-67-000018"
        $Title = "The ESXi host SSH daemon must not permit GSSAPI authentication."
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

# SSH Kerberos
Try{
    If($ESXI67000019){
        $VULID = "V-239274"
        $STIGID = "ESXI-67-000019"
        $Title = "The ESXi host SSH daemon must not permit Kerberos authentication."
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
    If($ESXI67000020){
        $VULID = "V-239275"
        $STIGID = "ESXI-67-000020"
        $Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
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
    If($ESXI67000021){
        $VULID = "V-239276"
        $STIGID = "ESXI-67-000021"
        $Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
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
    If($ESXI67000022){
        $VULID = "V-239277"
        $STIGID = "ESXI-67-000022"
        $Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
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
    If($ESXI67000023){
        $VULID = "V-239278"
        $STIGID = "ESXI-67-000023"
        $Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
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

# SSH AcceptEnv
Try{
    If($ESXI67000024){
        $VULID = "V-239279"
        $STIGID = "ESXI-67-000024"
        $Title = "The ESXi host SSH daemon must not accept environment variables from the client."
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
    If($ESXI67000025){
        $VULID = "V-239280"
        $STIGID = "ESXI-67-000025"
        $Title = "The ESXi host SSH daemon must not permit tunnels."
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
    If($ESXI67000026){
        $VULID = "V-239281"
        $STIGID = "ESXI-67-000026"
        $Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
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
    If($ESXI67000027){
        $VULID = "V-239282"
        $STIGID = "ESXI-67-000027"
        $Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
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

# SSH MaxSessions
Try{
    If($ESXI67000028){
        $VULID = "V-239283"
        $STIGID = "ESXI-67-000028"
        $Title = "The ESXi host SSH daemon must limit connections to a single session."
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

# SSH Authorized Keys
Try{
    If($ESXI67000029){
        $VULID = "V-239284"
        $STIGID = "ESXI-67-000029"
        $Title = "The ESXi host must remove keys from the SSH authorized_keys file."
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

## Log Level
Try{
    If($ESXI67000030){
        $VULID = "V-239285"
        $STIGID = "ESXI-67-000030"
        $Title = "The ESXi host must produce audit records containing information to establish what type of events occurred."
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
    If($ESXI67000031){
        $VULID = "V-239286"
        $STIGID = "ESXI-67-000031"
        $Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
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
    If($ESXI67000032){
        $VULID = "V-239287"
        $STIGID = "ESXI-67-000032"
        $Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
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
    If($ESXI67000033){
        $VULID = "V-239288"
        $STIGID = "ESXI-67-000033"
        $Title = "The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm."
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
    If($ESXI67000034){
        $VULID = "V-239289"
        $STIGID = "ESXI-67-000034"
        $Title = "The ESXi host must disable the Managed Object Browser (MOB)."
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
    If($ESXI67000035){
        $VULID = "V-239290"
        $STIGID = "ESXI-67-000035"
        $Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
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
    If($ESXI67000036){
        $VULID = "V-239291"
        $STIGID = "ESXI-67-000036"
        $Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
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
    If($ESXI67000037){
        $VULID = "V-239292"
        $STIGID = "ESXI-67-000037"
        $Title = "The ESXi host must use Active Directory for local user authentication."
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
    If($ESXI67000038){
        $VULID = "V-239293"
        $STIGID = "ESXI-67-000038"
        $Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
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
    If($ESXI67000039){
        $VULID = "V-239294"
        $STIGID = "ESXI-67-000039"
        $Title = "Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory."
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

# 2FA
Try{
    If($ESXI67000040){
        $VULID = "V-239295"
        $STIGID = "ESXI-67-000040"
        $Title = "The ESXi host must use multifactor authentication for local access to privileged accounts."
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

## Shell Interactive Timeout
Try{
    If($ESXI67000041){
        $VULID = "V-239296"
        $STIGID = "ESXI-67-000041"
        $Title = "The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes."
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
    If($ESXI67000042){
        $VULID = "V-239297"
        $STIGID = "ESXI-67-000042"
        $Title = "The ESXi host must terminate shell services after 10 minutes."
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
    If($ESXI67000043){
        $VULID = "V-239298"
        $STIGID = "ESXI-67-000043"
        $Title = "The ESXi host must log out of the console UI after two minutes."
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

# Dump Partition
Try{
    If($ESXI67000044){
        $VULID = "V-239299"
        $STIGID = "ESXI-67-000044"
        $Title = "The ESXi host must enable kernel core dumps."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.coredump.partition.list.Invoke() | Where-Object {$_.Active -eq "true"}
            If($results){
                Write-ToConsoleGreen "...Core dumps are configured on partition $($results.Name) on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...Core dumps are not configured on $($vmhost.name)...configuring network dump location to current vCenter server..."
                #No core dump partition configured so assuming ESXi is installed on a USB or similar device or with AutoDeploy
                #Find Management VMkernel
                $mgmtvmk = $vmhost | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.ManagementTrafficEnabled -eq $true} | Select-Object -First 1
                #Find Managing vCenter IP
                $vmhostv = $vmhost | Get-View
                $coreDumpIP = $vmhostv.Summary.ManagementServerIp
                #Set Network Core Dump Collector Settings
                $dumpargs = $esxcli.system.coredump.network.set.CreateArgs()
                $dumpargs.interfacename = $mgmtvmk.Name
                $dumpargs.serverip = $coreDumpIP
                $dumpargs.serverport = "6500"
                $dumpargs.enable = $true
                $esxcli.system.coredump.network.set.Invoke($dumpargs)
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
    If($ESXI67000045){
        $VULID = "V-239300"
        $STIGID = "ESXI-67-000045"
        $Title = "The ESXi host must enable a persistent log location for all locally stored logs."
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
    If($ESXI67000046){
        $VULID = "V-239301"
        $STIGID = "ESXI-67-000046"
        $Title = "The ESXi host must configure NTP time synchronization."
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
    If($ESXI67000047){
        $VULID = "V-239302"
        $STIGID = "ESXI-67-000047"
        $Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) Acceptance Levels must be verified."
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
    If($ESXI67000048){
        $VULID = "V-239303"
        $STIGID = "ESXI-67-000048"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
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
    If($ESXI67000049){
        $VULID = "V-239304"
        $STIGID = "ESXI-67-000049"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
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
    If($ESXI67000050){
        $VULID = "V-239305"
        $STIGID = "ESXI-67-000050"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
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

# TCP/IP Separation
Try{
    If($ESXI67000052){
        $VULID = "V-239306"
        $STIGID = "ESXI-67-000052"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by utilizing different TCP/IP stacks where possible."
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
    If($ESXI67000053){
        $VULID = "V-239307"
        $STIGID = "ESXI-67-000053"
        $Title = "SNMP must be configured properly on the ESXi host."
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
    If($ESXI67000054){
        $VULID = "V-239308"
        $STIGID = "ESXI-67-000054"
        $Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
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
    If($ESXI67000055){
        $VULID = "V-239309"
        $STIGID = "ESXI-67-000055"
        $Title = "The ESXi host must disable Inter-VM transparent page sharing."
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
    If($ESXI67000056){
        $VULID = "V-239310"
        $STIGID = "ESXI-67-000056"
        $Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $fwservices = $vmhost | Get-VMHostFirewallException | Where-Object {$_.Enabled -eq $True -and $_.extensiondata.allowedhosts.allip -eq "enabled" -and $_.Name -ne "vSphere Web Client"}
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
    If($ESXI67000057){
        $VULID = "V-239311"
        $STIGID = "ESXI-67-000057"
        $Title = "The ESXi host must configure the firewall to block network traffic by default."
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
    If($ESXI67000058){
        $VULID = "V-239312"
        $STIGID = "ESXI-67-000058"
        $Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
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
    If($ESXI67000059){
        $VULID = "V-239313"
        $STIGID = "ESXI-67-000059"
        $Title = "The virtual switch Forged Transmits policy must be set to reject on the ESXi host."
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
    If($ESXI67000060){
        $VULID = "V-239314"
        $STIGID = "ESXI-67-000060"
        $Title = "The virtual switch MAC Address Change policy must be set to reject on the ESXi host."
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
    If($ESXI67000061){
        $VULID = "V-239315"
        $STIGID = "ESXI-67-000061"
        $Title = "The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host."
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
    If($ESXI67000062){
        $VULID = "V-239316"
        $STIGID = "ESXI-67-000062"
        $Title = "The ESXi host must prevent unintended use of the dvFilter network APIs."
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
    If($ESXI67000063){
        $VULID = "V-239317"
        $STIGID = "ESXI-67-000063"
        $Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
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
    If($ESXI67000064){
        $VULID = "V-239318"
        $STIGID = "ESXI-67-000064"
        $Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
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
    If($ESXI67000065){
        $VULID = "V-239319"
        $STIGID = "ESXI-67-000065"
        $Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
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

# DTP
Try{
    If($ESXI67000066){
        $VULID = "V-239320"
        $STIGID = "ESXI-67-000066"
        $Title = "For physical switch ports connected to the ESXi host, the non-negotiate option must be configured for trunk links between external physical switches and virtual switches in VST mode."
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

# Spanning Tree
Try{
    If($ESXI67000067){
        $VULID = "V-239321"
        $STIGID = "ESXI-67-000067"
        $Title = "All ESXi host-connected physical switch ports must be configured with spanning tree disabled."
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

# Required VLANs
Try{
    If($ESXI67000068){
        $VULID = "V-239322"
        $STIGID = "ESXI-67-000068"
        $Title = "All ESXi host-connected virtual switch VLANs must be fully documented and have only the required VLANs."
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

# CIM User
Try{
    If($ESXI67000070){
        $VULID = "V-239323"
        $STIGID = "ESXI-67-000070"
        $Title = "The ESXi host must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications."
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

# ISO Checksum
Try{
    If($ESXI67000071){
        $VULID = "V-239324"
        $STIGID = "ESXI-67-000071"
        $Title = "The ESXi host must verify the integrity of the installation media before installing ESXi."
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
    If($ESXI67000072){
        $VULID = "V-239325"
        $STIGID = "ESXI-67-000072"
        $Title = "The ESXi host must have all security patches and updates installed."
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
    If($ESXI67000074){
        $VULID = "V-239326"
        $STIGID = "ESXI-67-000074"
        $Title = "The ESXi host must exclusively enable TLS 1.2 for all endpoints."
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
    If($ESXI67000076){
        $VULID = "V-239327"
        $STIGID = "ESXI-67-000076"
        $Title = "The ESXi host must enable Secure Boot."
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
    If($ESXI67000078){
        $VULID = "V-239328"
        $STIGID = "ESXI-67-000078"
        $Title = "The ESXi host must use DoD-approved certificates."
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
    If($ESXI67000079){
        $VULID = "V-239329"
        $STIGID = "ESXI-67-000079"
        $Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
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

## Enable lockdown mode
Try{
    If($ESXI67000001){
        $VULID = "V-239258"
        $STIGID = "ESXI-67-000001"
        $Title = "Access to the ESXi host must be limited by enabling Lockdown Mode."
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