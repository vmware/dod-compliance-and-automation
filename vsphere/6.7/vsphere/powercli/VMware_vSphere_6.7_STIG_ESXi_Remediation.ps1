<# 
.SYNOPSIS 
    Remediates ESXi 6.7 hosts against the DISA STIG for vSphere
.DESCRIPTION
    Remediates a single host or all hosts in a specified cluster.

    Assumes the VMware DoD STIG VIB is being used to remediate some settings.

    Duplicate Controls are not included.  For example if 2 controls ask to configure syslog only the first one is included here.
.NOTES 
    File Name  : VMware_6.7_STIG_Remediate_ESXi.ps1 
    Author     : Ryan Lakey
    Version    : 1.0

    Tested against
    -PowerCLI 11.3
    -Powershell 5
    -ESXi 6.7 U2+

.INPUTS
    No inputs required

.PARAMETER hostname
    Enter the hostname of the new ESXi host in short format not FQDN
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$vcenter,
    [Parameter(Mandatory=$true)]
    [pscredential]$vccred,
    [Parameter(Mandatory=$false,ParameterSetName="SingleHost")]
    [string]$hostname,
    [Parameter(Mandatory=$false,ParameterSetName="Cluster")]
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
    lockdownlevel           = "lockdownNormal"  #Lockdown level.  lockdownDisabled,lockdownNormal,lockdownStrict
    DCUIAccess              = @{"DCUI.Access" = "root"}
    vibacceptlevel          = "PartnerSupported"  #VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"}
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"}
    logLevel                = @{"Config.HostAgent.log.level" = "info"}
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = "False"}
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "600"}
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"}
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "600"}
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"}
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"}
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""}
    syslogScratch           = @{"Syslog.global.logDir" = "[] /scratch/log"}
    sshEnabled              = $false
    shellEnabled            = $false
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"}
    esxiLatestBuild         = "14320388"
    nativeVLANid            = $nativeVLAN
    ##### Environment Specific STIG Values #####
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}
    stigVibRE               = "dod-esxi65-stig-re"   #Update with STIG VIB version used
    stigVibRD               = "dod-esxi65-stig-rd"   #Update with STIG VIB version used
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup}
    allowedips              = $allowedIPs  #Allows IP ranges for the ESXi firewall
    ntpServers              = $ntpServers
}

##### Enable or Disable specific STIG Remediations #####
$V93949 = $true  #Lockdown Mode
$V93951 = $true  #DCUI.Access List
$V93953 = $true  #Lockdown Mode Exceptions
$V93955 = $true  #Syslog
$V93957 = $true  #Account Lock Failures
$V93959 = $true  #Account Unlock Timeout
$V93961 = $true  #Consent Banner Welcome
$V93963 = $true  #Consent Banner /etc/issue
$V93965 = $true  #SSH Banner
$V93967 = $true  #SSH Ciphers aes128-ctr,aes192-ctr,aes256-ctr
$V93969 = $true  #SSH Protocol 2
$V93971 = $true  #SSH IgnoreRhosts yes
$V93973 = $true  #SSH HostbasedAuthentication no
$V93975 = $true  #SSH PermitRootLogin no
$V93977 = $true  #SSH PermitEmptyPasswords no
$V93979 = $true  #SSH PermitUserEnvironment no
$V93981 = $true  #SSH MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512
$V93983 = $true  #SSH GSSAPIAuthentication no
$V93985 = $true  #SSH KerberosAuthentication no
$V93987 = $true  #SSH StrictModes yes
$V93989 = $true  #SSH Compression no
$V93991 = $true  #SSH GatewayPorts no
$V93993 = $true  #SSH X11Forwarding no
$V93995 = $true  #SSH AcceptEnv
$V93997 = $true  #SSH PermitTunnel no
$V93999 = $true  #SSH ClientAliveCountMax 3
$V94001 = $true  #SSH ClientAliveInterval 200
$V94003 = $true  #SSH MaxSessions 1
$V94005 = $true  #Authorized Keys
$V94007 = $true  #Log Level
$V94009 = $true  #Password Complexity
$V94011 = $true  #Password Reuse
$V94013 = $true  #Password Hashes
$V94015 = $true  #Mob
$V94017 = $true  #SSH Running
$V94021 = $true  #Active Directory
$V94023 = $true  #Authentication Proxy
$V94025 = $true  #AD Admin Group
$V94027 = $true  #2FA
$V94029 = $true  #Shell Interactive Timeout
$V94031 = $true  #Shell Timeout
$V94033 = $true  #DCUI Timeout
$V94035 = $true  #Core Dumps
$V94037 = $true  #Persistent Logs
$V94039 = $true  #NTP
$V94041 = $true  #Acceptance Level
$V94043 = $true  #Isolate vMotion
$V94045 = $true  #Protect Management
$V94047 = $true  #Protect Storage traffic
$V94049 = $true  #VMK Separation
$V94051 = $true  #TCP/IP Stacks
$V94053 = $true  #SNMP
$V94055 = $true  #iSCSI CHAP
$V94057 = $true  #Memory Salting
$V94059 = $true  #Firewall Rules
$V94061 = $true  #Default Firewall
$V94063 = $true  #BPDU
$V94065 = $true  #Forged Transmits
$V94067 = $true  #MAC Changes
$V94069 = $true  #Prom Mode
$V94071 = $true  #dvFilter
$V94073 = $true  #Native VLAN
$V94075 = $true  #VLAN 4095
$V94077 = $true  #Reserved VLANs
$V94079 = $true  #DTP
$V94081 = $true  #STP
$V94083 = $true  #Required VLANs
$V94349 = $true  #CIM Account
$V94477 = $true  #Checksum
$V94479 = $true  #Patch Level
#Removed from 6.7 $V94481 = $true  #TLS 1.2 SFCB
$V94483 = $true  #TLS 1.2 ipFilter vSAN
#Removed from 6.7 $V94485 = $true  #TLS 1.2 authd
$V94487 = $true  #Secureboot
$V94489 = $true  #DoD Cert

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
        $vmhosts = Get-VMHost -Name $hostname | Where {$_.version -match "^6.7*"} | Sort Name
        $vmhostsv = $vmhosts | Get-View | Sort Name
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Found host $vmhost"
        }
    }
    If($cluster){
        $vmhosts = Get-Cluster -Name $cluster | Get-VMHost | Where {$_.version -match "^6.7*"} | Sort Name
        $vmhostsv = $vmhosts | Get-View | Sort Name
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Found host $vmhost"
        }
    } 
}
Catch
{
    Write-Error "Failed to gather infor on target hosts in $vcenter"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## DCUI.Access
Try{
    If($V93951){
        $VULID = "V-93951"
        $STIGID = "ESXI-65-000002"
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
    If($V93953){
        $VULID = "V-93953"
        $STIGID = "ESXI-65-000003"
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
    If($V93955){
        $VULID = "V-93955"
        $STIGID = "ESXI-65-000004"
        $Title = "Remote logging for ESXi hosts must be configured."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        If($logInsight){
            Write-ToConsole "...Log Insight used to manage syslog skipping this control"
        }Else{
            ForEach($vmhost in $vmhosts){
                $name = $stigsettings.syslogHost.Keys
                $value = $stigsettings.syslogHost.Values
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
    If($V93957){
        $VULID = "V-93957"
        $STIGID = "ESXI-65-000005"
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
    If($V93959){
        $VULID = "V-93959"
        $STIGID = "ESXI-65-000006"
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
    If($V93961){
        $VULID = "V-93961"
        $STIGID = "ESXI-65-000007"
        $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93963){
        $VULID = "V-93963"
        $STIGID = "ESXI-65-000008"
        $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93965){
        $VULID = "V-93965"
        $STIGID = "ESXI-65-000009"
        $Title = "The ESXi host SSH daemon must be configured with the Department of Defense (DoD) login banner."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93967){
        $VULID = "V-93967"
        $STIGID = "ESXI-65-000010"
        $Title = "The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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

## SSH Protocol
Try{
    If($V93969){
        $VULID = "V-93969"
        $STIGID = "ESXI-65-000011"
        $Title = "The ESXi host SSH daemon must be configured to use only the SSHv2 protocol."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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

## SSH .rhosts
Try{
    If($V93971){
        $VULID = "V-93971"
        $STIGID = "ESXI-65-000012"
        $Title = "The ESXi host SSH daemon must ignore .rhosts files."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93973){
        $VULID = "V-93973"
        $STIGID = "ESXI-65-000013"
        $Title = "The ESXi host SSH daemon must not allow host-based authentication."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93975){
        $VULID = "V-93975"
        $STIGID = "ESXI-65-000014"
        $Title = "The ESXi host SSH daemon must not permit root logins."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93977){
        $VULID = "V-93977"
        $STIGID = "ESXI-65-000015"
        $Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93979){
        $VULID = "V-93979"
        $STIGID = "ESXI-65-000016"
        $Title = "The ESXi host SSH daemon must not permit user environment settings."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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

## SSH MACs
Try{
    If($V93981){
        $VULID = "V-93981"
        $STIGID = "ESXI-65-000017"
        $Title = "The ESXi host SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93983){
        $VULID = "V-93983"
        $STIGID = "ESXI-65-000018"
        $Title = "The ESXi host SSH daemon must not permit GSSAPI authentication."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93985){
        $VULID = "V-93985"
        $STIGID = "ESXI-65-000019"
        $Title = "The ESXi host SSH daemon must not permit Kerberos authentication."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93987){
        $VULID = "V-93987"
        $STIGID = "ESXI-65-000020"
        $Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93989){
        $VULID = "V-93989"
        $STIGID = "ESXI-65-000021"
        $Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93991){
        $VULID = "V-93991"
        $STIGID = "ESXI-65-000022"
        $Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93993){
        $VULID = "V-93993"
        $STIGID = "ESXI-65-000023"
        $Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93995){
        $VULID = "V-93995"
        $STIGID = "ESXI-65-000024"
        $Title = "The ESXi host SSH daemon must not accept environment variables from the client."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93997){
        $VULID = "V-93997"
        $STIGID = "ESXI-65-000025"
        $Title = "The ESXi host SSH daemon must not permit tunnels."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V93999){
        $VULID = "V-93999"
        $STIGID = "ESXI-65-000026"
        $Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V94001){
        $VULID = "V-94001"
        $STIGID = "ESXI-65-000027"
        $Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V94003){
        $VULID = "V-94003"
        $STIGID = "ESXI-65-000028"
        $Title = "The ESXi host SSH daemon must limit connections to a single session."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V94005){
        $VULID = "V-94005"
        $STIGID = "ESXI-65-000029"
        $Title = "The ESXi host must remove keys from the SSH authorized_keys file."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94007){
        $VULID = "V-94007"
        $STIGID = "ESXI-65-000030"
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
    If($V94009){
        $VULID = "V-94009"
        $STIGID = "ESXI-65-000031"
        $Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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

# Password Reuse
Try{
    If($V94011){
        $VULID = "V-94011"
        $STIGID = "ESXI-65-000032"
        $Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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

# Password Hashes
Try{
    If($V94013){
        $VULID = "V-94013"
        $STIGID = "ESXI-65-000033"
        $Title = "The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
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
    If($V94015){
        $VULID = "V-94015"
        $STIGID = "ESXI-65-000034"
        $Title = "The ESXi host must disable the Managed Object Browser (MOB)."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.enableMob.Keys
            $value = [string]$stigsettings.enableMob.Values
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
    If($V94017){
        $VULID = "V-94017"
        $STIGID = "ESXI-65-000035"
        $Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $servicename = "SSH"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where {$_.Label -eq $servicename}
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
    If($V94019){
        $VULID = "V-94019"
        $STIGID = "ESXI-65-000036"
        $Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $servicename = "ESXi Shell"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where {$_.Label -eq $servicename}
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
    If($V94021){
        $VULID = "V-94021"
        $STIGID = "ESXI-65-000037"
        $Title = "The ESXi host must use Active Directory for local user authentication."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94023){
        $VULID = "V-94023"
        $STIGID = "ESXI-65-000038"
        $Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94025){
        $VULID = "V-94025"
        $STIGID = "ESXI-65-000039"
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
    If($V94027){
        $VULID = "V-94027"
        $STIGID = "ESXI-65-000040"
        $Title = "The ESXi host must use multifactor authentication for local access to privileged accounts."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94029){
        $VULID = "V-94029"
        $STIGID = "ESXI-65-000041"
        $Title = "The ESXi host must set a timeout to automatically disable idle sessions after 10 minutes."
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
    If($V94031){
        $VULID = "V-94031"
        $STIGID = "ESXI-65-000042"
        $Title = "The ESXi host must set a timeout to automatically disable idle sessions after 10 minutes."
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
    If($V94033){
        $VULID = "V-94033"
        $STIGID = "ESXI-65-000043"
        $Title = "The ESXi host must logout of the console UI after 10 minutes."
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
    If($V94035){
        $VULID = "V-94035"
        $STIGID = "ESXI-65-000044"
        $Title = "The ESXi host must enable kernel core dumps."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.coredump.partition.list.Invoke() | Where {$_.Active -eq "true"}
            If($results){
                Write-ToConsoleGreen "...Core dumps are configured on partition $($results.Name) on $($vmhost.name)"
            }Else{
                Write-ToConsoleRed "...Core dumps are not configured on $($vmhost.name)...configuring network dump location to current vCenter server..."
                #No core dump partition configured so assuming ESXi is installed on a USB or similar device or with AutoDeploy
                #Find Management VMkernel
                $mgmtvmk = $vmhost | Get-VMHostNetworkAdapter -VMKernel | Where {$_.ManagementTrafficEnabled -eq $true} | Select -First 1
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
    If($V94037){
        $VULID = "V-94037"
        $STIGID = "ESXI-65-000045"
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
    If($V94039){
        $VULID = "V-94039"
        $STIGID = "ESXI-65-000046"
        $Title = "The ESXi host must configure NTP time synchronization."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $currentntp = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
            If($currentntp.count -eq "0"){
                Write-ToConsoleRed "...No NTP servers configured on $($vmhost.name)...configuring NTP"
                $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers
                $vmhost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
                $vmhost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
            }
            else{
                If($stigsettings.ntpServers[0] -ne $currentntp[0] -or $stigsettings.ntpServers[1] -ne $currentntp[1]){
                    Write-ToConsoleRed "...NTP Servers configured incorrectly on $($vmhost.name)...reconfiguring NTP"
                    ForEach($ntp in $currentntp){
                        $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false
                    }
                    $vmhost | Add-VMHostNtpServer $stigsettings.ntpServers
                    $vmhost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
                    $vmhost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
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
    If($V94041){
        $VULID = "V-94041"
        $STIGID = "ESXI-65-000047"
        $Title = "The ESXi Image Profile and VIB Acceptance Levels must be verified."
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
    If($V94043){
        $VULID = "V-94043"
        $STIGID = "ESXI-65-000048"
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
    If($V94045){
        $VULID = "V-94045"
        $STIGID = "ESXI-65-000049"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94047){
        $VULID = "V-94047"
        $STIGID = "ESXI-65-000050"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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

# VMK Separation
Try{
    If($V94049){
        $VULID = "V-94049"
        $STIGID = "ESXI-65-000051"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94051){
        $VULID = "V-94051"
        $STIGID = "ESXI-65-000052"
        $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by utilizing different TCP/IP stacks where possible."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94053){
        $VULID = "V-94053"
        $STIGID = "ESXI-65-000053"
        $Title = "SNMP must be configured properly on the ESXi host."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94055){
        $VULID = "V-94055"
        $STIGID = "ESXI-65-000054"
        $Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94057){
        $VULID = "V-94057"
        $STIGID = "ESXI-65-000055"
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
    If($V94059){
        $VULID = "V-94059"
        $STIGID = "ESXI-65-000056"
        $Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $fwservices = $vmhost | Get-VMHostFirewallException | Where {$_.Enabled -eq $True -and $_.extensiondata.allowedhosts.allip -eq "enabled" -and $_.Name -ne "vSphere Web Client"}
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
    If($V94061){
        $VULID = "V-94061"
        $STIGID = "ESXI-65-000057"
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
    If($V94063){
        $VULID = "V-94063"
        $STIGID = "ESXI-65-000058"
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
    If($V94065){
        $VULID = "V-94065"
        $STIGID = "ESXI-65-000059"
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
                        $secpol | Set-SecurityPolicy -ForgedTransmits $true -Confirm:$false
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
    If($V94067){
        $VULID = "V-94067"
        $STIGID = "ESXI-65-000060"
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
                        $secpol | Set-SecurityPolicy -MacChanges $true -Confirm:$false
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
    If($V94069){
        $VULID = "V-94069"
        $STIGID = "ESXI-65-000061"
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
                        $secpol | Set-SecurityPolicy -AllowPromiscuous $true -Confirm:$false
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
    If($V94071){
        $VULID = "V-94071"
        $STIGID = "ESXI-65-000062"
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
    If($V94073){
        $VULID = "V-94073"
        $STIGID = "ESXI-65-000063"
        $Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for native VLAN Id: $($stigsettings.nativeVLANid)"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where {$_.VlanId -eq $stigsettings.nativeVLANid}
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
    If($V94075){
        $VULID = "V-94075"
        $STIGID = "ESXI-65-000064"
        $Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for trunked port groups"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where {$_.VlanId -eq "4095"}
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
    If($V94077){
        $VULID = "V-94077"
        $STIGID = "ESXI-65-000065"
        $Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for reserved VLAN IDs on port groups"
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard | Where {$_.VlanId -In 1001..1024 -or $_.VlanId -In 3968...4047 -or $_.VlanId -In 4094}
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
    If($V94079){
        $VULID = "V-94079"
        $STIGID = "ESXI-65-000066"
        $Title = "For physical switch ports connected to the ESXi host, the non-negotiate option must be configured for trunk links between external physical switches and virtual switches in VST mode."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94081){
        $VULID = "V-94081"
        $STIGID = "ESXI-65-000067"
        $Title = "All ESXi host-connected physical switch ports must be configured with spanning tree disabled."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94083){
        $VULID = "V-94083"
        $STIGID = "ESXI-65-000068"
        $Title = "All ESXi host-connected virtual switch VLANs must be fully documented and have only the required VLANs."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94349){
        $VULID = "V-94349"
        $STIGID = "ESXI-65-000070"
        $Title = "The ESXi host must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94477){
        $VULID = "V-94477"
        $STIGID = "ESXI-65-000071"
        $Title = "The ESXi host must verify the integrity of the installation media before installing ESXi."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94479){
        $VULID = "V-94479"
        $STIGID = "ESXI-65-000072"
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
    If($V94483){
        $VULID = "V-94483"
        $STIGID = "ESXI-65-000074"
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
    If($V94487){
        $VULID = "V-94487"
        $STIGID = "ESXI-65-000076"
        $Title = "The ESXi host must enable Secure Boot."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V94489){
        $VULID = "V-94489"
        $STIGID = "ESXI-65-000078"
        $Title = "The ESXi host must use DoD-approved certificates."
        Write-ToConsole "...Remediating Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
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
    If($V93949){
        $VULID = "V-93949"
        $STIGID = "ESXI-65-000001"
        $Title = "The ESXi host must limit the number of concurrent sessions to ten for all accounts and/or account types by enabling lockdown mode."
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