<# 
.SYNOPSIS 
    Remediates ESXi hosts against the vSphere ESXi 7.0 STIG Readiness Guide
    Version 1 Release 4
.DESCRIPTION
    -Remediates a single host or all hosts in a specified cluster.
    -Individual controls can be enabled/disabled in the $controlsenabled hash table
    -SSH settings are not remediated by this script since as of U2/U3 they are correct OOTB. Configuration drift will be detected by InSpec.
    -Not all controls are remediated by this script. Please review the output and items skipped for manual remediation.

.NOTES 
    File Name  : VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 
    Author     : VMware
    Version    : 1 Release 4
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 7.0 U3g

    Example command to run script
    .\VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local -vccred $cred -esxAdminGroup "esxAdmins2" -allowedIPs "10.0.0.0/8" -syslogServer "tcp://log.test.local:514" -ntpServers "time.test.local","time2.test.local" -reportpath C:\Reports

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
    esxiLatestBuild         = "19482537" #ESXI-70-000072
    nativeVLANid            = $nativeVLAN #ESXI-70-000063
    suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} #ESXI-70-000079
    executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"} #ESXI-70-000080
    suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} #ESXI-70-000081
    auditRecords            = [ordered]@{
                                "size" = "100"
                                "dir"  = "/scratch/auditLog"
                                }
    slpdEnabled             = $false #ESXI-70-000083
    syslogCertCheck         = @{"Syslog.global.logCheckSSLCerts" = "true"} #ESXI-70-000086
    memEagerZero            = @{"Mem.MemEagerZero" = "1"} #ESXI-70-000087
    apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-70-000088
    hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "600"} #ESXI-70-000089
    passwordMaxAge          = @{"Security.PasswordMaxDays" = "90"} #ESXI-70-000091
    cimEnabled              = $false #ESXI-70-000097
    ##### Environment Specific STIG Values #####
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}   #ESXI-70-000004
    stigVibRE               = "dod-esxi70-stig-re"   #Update with STIG VIB version used
    stigVibRD               = "dod-esxi70-stig-rd"   #Update with STIG VIB version used
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup} #ESXI-70-000039
    allowedips              = $allowedIPs  #ESXI-70-000056 Allows IP ranges for the ESXi firewall
    ntpServers              = $ntpServers #ESXI-70-000046
}

##### Setup report variables ####
$changedcount = 0
$unchangedcount= 0
$skipcount = 0
$failedcount = 0

##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
    ESXI70000001 = $true  #Lockdown Mode
    ESXI70000002 = $true  #DCUI.Access List
    ESXI70000003 = $true  #Lockdown Mode Exceptions
    ESXI70000004 = $true  #Syslog
    ESXI70000005 = $true  #Account Lock Failures
    ESXI70000006 = $true  #Account Unlock Timeout
    ESXI70000007 = $false  #Consent Banner Welcome
    ESXI70000008 = $false  #Consent Banner /etc/issue
    ESXI70000009 = $false  #SSH Banner
    ESXI70000010 = $true  #SSH FipsMode
    ESXI70000012 = $false  #SSH IgnoreRhosts yes
    ESXI70000013 = $false  #SSH HostbasedAuthentication no
    ESXI70000014 = $false  #SSH PermitRootLogin no
    ESXI70000015 = $false  #SSH PermitEmptyPasswords no
    ESXI70000016 = $false  #SSH PermitUserEnvironment no
    ESXI70000020 = $false  #SSH StrictModes yes
    ESXI70000021 = $false  #SSH Compression no
    ESXI70000022 = $false  #SSH GatewayPorts no
    ESXI70000023 = $false  #SSH X11Forwarding no
    ESXI70000025 = $false  #SSH PermitTunnel no
    ESXI70000026 = $false  #SSH ClientAliveCountMax 3
    ESXI70000027 = $false  #SSH ClientAliveInterval 200
    ESXI70000030 = $true  #Log Level
    ESXI70000031 = $true  #Password Complexity
    ESXI70000032 = $true  #Password Reuse
    ESXI70000034 = $true  #Mob
    ESXI70000035 = $true  #SSH Running
    ESXI70000036 = $true  #Shell Running
    ESXI70000037 = $true  #Active Directory
    ESXI70000038 = $true  #Authentication Proxy
    ESXI70000039 = $true  #AD Admin Group
    ESXI70000041 = $true  #Shell Interactive Timeout
    ESXI70000042 = $true  #Shell Timeout
    ESXI70000043 = $true  #DCUI Timeout
    ESXI70000045 = $true  #Persistent Logs
    ESXI70000046 = $true  #NTP
    ESXI70000047 = $true  #Acceptance Level
    ESXI70000048 = $true  #Isolate vMotion
    ESXI70000049 = $true  #Protect Management
    ESXI70000050 = $true  #Protect Storage traffic
    ESXI70000053 = $true  #SNMP
    ESXI70000054 = $true  #iSCSI CHAP
    ESXI70000055 = $true  #Memory Salting
    ESXI70000056 = $true  #Firewall Rules
    ESXI70000057 = $true  #Default Firewall
    ESXI70000058 = $true  #BPDU
    ESXI70000059 = $true  #Forged Transmits
    ESXI70000060 = $true  #MAC Changes
    ESXI70000061 = $true  #Prom Mode
    ESXI70000062 = $true  #dvFilter
    ESXI70000063 = $true  #Native VLAN
    ESXI70000064 = $true  #VLAN 4095
    ESXI70000065 = $true  #Reserved VLANs
    ESXI70000070 = $true  #CIM Account
    ESXI70000072 = $true  #Patch Level
    ESXI70000074 = $true  #TLS 1.2
    ESXI70000076 = $true  #Secureboot
    ESXI70000078 = $true  #DoD Cert
    ESXI70000079 = $true  #Suppress Shell Warning
#   ESXI70000080 = $true  #execute approved vibs
    ESXI70000081 = $true  #Suppress Hyperthreading Warning
    ESXI70000082 = $false  #SSH AllowTCPForwarding
    ESXI70000083 = $true  #Disable SLPD Service
    ESXI70000084 = $true  #Audit Logging
    ESXI70000085 = $true  #Syslog x509 strict
    ESXI70000086 = $true  #Syslog Cert Verification
    ESXI70000087 = $true  #Volatile mem desctruction
    ESXI70000088 = $true  #API Timeout
    ESXI70000089 = $true  #Host Client Timeout
    ESXI70000090 = $true  #Rhttpproxy FIPs
    ESXI70000091 = $true  #Password age
    ESXI70000092 = $true  #VM Override
    ESXI70000093 = $true  #Vm Override Logger
    ESXI70000094 = $true  #TPM Config encryption
    ESXI70000095 = $true  #Secure boot enforcement
    ESXI70000097 = $true  #CIM service disabled
    ESXI70000274 = $false #SSH ciphers
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

## DCUI.Access
Try{
	$STIGID = "ESXI-70-000002"
	$Title = "The ESXi host must verify the DCUI.Access list."
    If($controlsenabled.ESXI70000002){
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

## Lockdown Exception Users
Try{
	$STIGID = "ESXI-70-000003"
	$Title = "The ESXi host must verify the exception users list for lockdown mode."
    If($controlsenabled.ESXI70000003){
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

## Syslog
Try{
	$STIGID = "ESXI-70-000004"
	$Title = "Remote logging for ESXi hosts must be configured."
    If($controlsenabled.ESXI70000004){
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

## Account Lock Failures
Try{
	$STIGID = "ESXI-70-000005"
	$Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
    If($controlsenabled.ESXI70000005){
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

## Account Unlock Timeout
Try{
	$STIGID = "ESXI-70-000006"
	$Title = "The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out."
    If($controlsenabled.ESXI70000006){
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

## Welcome banner   Disabling for internal use case
Try{
	$STIGID = "ESXI-70-000007"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    If($controlsenabled.ESXI70000007){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## /etc/issue Banner
Try{
	$STIGID = "ESXI-70-000008"
	$Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    If($controlsenabled.ESXI70000008){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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
	$STIGID = "ESXI-70-000009"
	$Title = "The ESXi host SSH daemon must be configured with the DoD logon banner."
    If($controlsenabled.ESXI70000009){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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
	$STIGID = "ESXI-70-000010"
	$Title = "The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions."
    If($controlsenabled.ESXI70000010){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.security.fips140.ssh.get.invoke()
            If($results -ne "true"){
                Write-ToConsoleGreen "...SSH FipsMode set correctly to $results on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...Configuring SSH FipsMode on $($vmhost.name)"
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

## SSH .rhosts
Try{
	$STIGID = "ESXI-70-000012"
	$Title = "The ESXi host SSH daemon must ignore .rhosts files."
    If($controlsenabled.ESXI70000012){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## SSH hostbasedauth
Try{
	$STIGID = "ESXI-70-000013"
	$Title = "The ESXi host SSH daemon must not allow host-based authentication."
    If($controlsenabled.ESXI70000013){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## SSH PermitRootLogin
Try{
	$STIGID = "ESXI-70-000014"
	$Title = "The ESXi host SSH daemon must not permit root logins."
    If($controlsenabled.ESXI70000014){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                If($results.Name -eq $stigsettings.stigVibRE){
                    Write-ToConsoleRed "...VMware STIG VIB Root Enabled is installed on $($vmhost.name). !!Ensure this is waivered!!"
                }Else{
                    Write-ToConsoleGreen "...VMware STIG VIB Root Disabled is installed on $($vmhost.name)"
                }
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## SSH PermitEmptyPasswords
Try{
	$STIGID = "ESXI-70-000015"
	$Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
    If($controlsenabled.ESXI70000015){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## SSH PermitUserEnvironment
Try{
	$STIGID = "ESXI-70-000016"
	$Title = "The ESXi host SSH daemon must not permit user environment settings."
    If($controlsenabled.ESXI70000016){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH StrictMode
Try{
	$STIGID = "ESXI-70-000020"
	$Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
    If($controlsenabled.ESXI70000020){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH Compression
Try{
	$STIGID = "ESXI-70-000021"
	$Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
    If($controlsenabled.ESXI70000021){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH Gateway Ports
Try{
	$STIGID = "ESXI-70-000022"
	$Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
    If($controlsenabled.ESXI70000022){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH X11
Try{
	$STIGID = "ESXI-70-000023"
	$Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
    If($controlsenabled.ESXI70000023){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH PermitTunnel
Try{
	$STIGID = "ESXI-70-000025"
	$Title = "The ESXi host SSH daemon must not permit tunnels."
    If($controlsenabled.ESXI70000025){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH ClientAliveCount
Try{
	$STIGID = "ESXI-70-000026"
	$Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
    If($controlsenabled.ESXI70000026){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

# SSH ClientAliveInterval
Try{
	$STIGID = "ESXI-70-000027"
	$Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
    If($controlsenabled.ESXI70000027){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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
	$STIGID = "ESXI-70-000030"
	$Title = "The ESXi host must produce audit records containing information to establish what type of events occurred."
    If($controlsenabled.ESXI70000030){
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
	$STIGID = "ESXI-70-000031"
	$Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
    If($controlsenabled.ESXI70000031){
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

# Password Reuse
Try{
	$STIGID = "ESXI-70-000032"
	$Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
    If($controlsenabled.ESXI70000032){
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
	$STIGID = "ESXI-70-000034"
	$Title = "The ESXi host must disable the Managed Object Browser (MOB)."
    If($controlsenabled.ESXI70000034){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $name = $stigsettings.enableMob.Keys
            $value = [boolean]$stigsettings.enableMob.Values
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

## SSH Disabled
Try{
	$STIGID = "ESXI-70-000035"
	$Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
    If($controlsenabled.ESXI70000035){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        $servicename = "SSH"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
            If($vmhostservice.Running -eq $true){
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
	$STIGID = "ESXI-70-000036"
	$Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
    If($controlsenabled.ESXI70000036){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        $servicename = "ESXi Shell"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
            If($vmhostservice.Running -eq $true){
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

# Active Directory
Try{
	$STIGID = "ESXI-70-000037"
	$Title = "The ESXi host must use Active Directory for local user authentication."
    If($controlsenabled.ESXI70000037){
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

# Active Directory
Try{
	$STIGID = "ESXI-70-000038"
	$Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
    If($controlsenabled.ESXI70000038){
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
	$STIGID = "ESXI-70-000039"
	$Title = "Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory."
    If($controlsenabled.ESXI70000039){
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

## Shell Interactive Timeout
Try{
	$STIGID = "ESXI-70-000041"
	$Title = "The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes."
    If($controlsenabled.ESXI70000041){
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

## Shell Timeout
Try{
	$STIGID = "ESXI-70-000042"
	$Title = "The ESXi host must terminate shell services after 10 minutes."
    If($controlsenabled.ESXI70000042){
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
	$STIGID = "ESXI-70-000043"
	$Title = "The ESXi host must log out of the console UI after two minutes."
    If($controlsenabled.ESXI70000043){
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

# Log Persistent Location
Try{
	$STIGID = "ESXI-70-000045"
	$Title = "The ESXi host must enable a persistent log location for all locally stored logs."
    If($controlsenabled.ESXI70000045){
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

# NTP
Try{
	$STIGID = "ESXI-70-000046"
	$Title = "The ESXi host must configure NTP time synchronization."
    If($controlsenabled.ESXI70000046){
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
	$STIGID = "ESXI-70-000047"
	$Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) Acceptance Levels must be verified."
    If($controlsenabled.ESXI70000047){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.acceptance.get.Invoke()
            If($results -ne "CommunitySupported"){
                Write-ToConsoleGreen "...VIB Acceptance level is set correctly to $results on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...Configuring VIB Acceptance level back to the default of PartnerSupported on $($vmhost.name)"
                $vibargs = $esxcli.software.acceptance.set.CreateArgs()
                $vibargs.level = "PartnerSupported"
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

# vMotion Separation
Try{
	$STIGID = "ESXI-70-000048"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
    If($controlsenabled.ESXI70000048){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
            ForEach($vmk in $vmks){
                If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
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

# Management Separation
Try{
	$STIGID = "ESXI-70-000049"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
    If($controlsenabled.ESXI70000049){
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
	$STIGID = "ESXI-70-000050"
	$Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
    If($controlsenabled.ESXI70000050){
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
	$STIGID = "ESXI-70-000053"
	$Title = "SNMP must be configured properly on the ESXi host."
    If($controlsenabled.ESXI70000053){
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

# iSCSI CHAP
Try{
	$STIGID = "ESXI-70-000054"
	$Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
    If($controlsenabled.ESXI70000054){
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

# Page Sharing
Try{
	$STIGID = "ESXI-70-000055"
	$Title = "The ESXi host must disable Inter-VM transparent page sharing."
    If($controlsenabled.ESXI70000055){
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

# Firewall Rules
Try{
	$STIGID = "ESXI-70-000056"
	$Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
    If($controlsenabled.ESXI70000056){
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

# Default Firewall Policy
Try{
	$STIGID = "ESXI-70-000057"
	$Title = "The ESXi host must configure the firewall to block network traffic by default."
    If($controlsenabled.ESXI70000057){
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

# Page Sharing
Try{
	$STIGID = "ESXI-70-000058"
	$Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
    If($controlsenabled.ESXI70000058){
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
	$STIGID = "ESXI-70-000059"
	$Title = "The virtual switch Forged Transmits policy must be set to reject on the ESXi host."
    If($controlsenabled.ESXI70000059){
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
	$STIGID = "ESXI-70-000060"
	$Title = "The virtual switch MAC Address Change policy must be set to reject on the ESXi host."
    If($controlsenabled.ESXI70000060){
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
	$STIGID = "ESXI-70-000061"
	$Title = "The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host."
    If($controlsenabled.ESXI70000061){
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
	$STIGID = "ESXI-70-000062"
	$Title = "The ESXi host must prevent unintended use of the dvFilter network APIs."
    If($controlsenabled.ESXI70000062){
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

# VLAN IDs
Try{
	$STIGID = "ESXI-70-000063"
	$Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
    If($controlsenabled.ESXI70000063){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for native VLAN Id: $($stigsettings.nativeVLANid)"
                $unchangedcount++
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -eq $stigsettings.nativeVLANid}
                If($portgroups.count -eq 0){
                    Write-ToConsoleGreen "...No port groups found with native VLAN Id $($stigsettings.nativeVLANid) on $($vmhost.name)"
                    $unchangedcount++
                }Else{
                    ForEach($pg in $portgroups){
                        Write-ToConsoleRed "...Portgroup $($pg.name) found with native VLAN Id: $($stigsettings.nativeVLANid) on $($vmhost.name).  Investigate and change or document waiver."
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

# VLAN Trunk
Try{
	$STIGID = "ESXI-70-000064"
	$Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
    If($controlsenabled.ESXI70000064){
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

# Reserved VLANs
Try{
	$STIGID = "ESXI-70-000065"
	$Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
    If($controlsenabled.ESXI70000065){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
            If($switches.count -eq 0){
                Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for reserved VLAN IDs on port groups"
                $unchangedcount++
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -In 1001..1024 -or $_.VlanId -In 3968...4047 -or $_.VlanId -In 4094}
                If($portgroups.count -eq 0){
                    Write-ToConsoleGreen "...No standard port groups found with reserved VLAN IDs on $($vmhost.name)"
                    $unchangedcount++
                }Else{
                    ForEach($pg in $portgroups){
                        Write-ToConsoleRed "...Portgroup $($pg.name) found with reserved VLAN ID: $($pg.VlanId) on $($vmhost.name).  Investigate and change or document waiver."
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

# CIM User
Try{
	$STIGID = "ESXI-70-000070"
	$Title = "The ESXi host must not provide root/administrator level access to CIM-based hardware monitoring tools or other third-party applications."
    If($controlsenabled.ESXI70000070){
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

# ESXi Patches
Try{
	$STIGID = "ESXI-70-000072"
	$Title = "The ESXi host must have all security patches and updates installed."
    If($controlsenabled.ESXI70000072){
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

# TLS 1.2
Try{
	$STIGID = "ESXI-70-000074"
	$Title = "The ESXi host must exclusively enable TLS 1.2 for all endpoints."
    If($controlsenabled.ESXI70000074){
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

# Secure Boot
Try{
	$STIGID = "ESXI-70-000076"
	$Title = "The ESXi host must enable Secure Boot."
    If($controlsenabled.ESXI70000076){
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

# Replace Certs
Try{
	$STIGID = "ESXI-70-000078"
	$Title = "The ESXi host must use DoD-approved certificates."
    If($controlsenabled.ESXI70000078){
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

# Suppress Shell Warning 
Try{
	$STIGID = "ESXI-70-000079"
	$Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
    If($controlsenabled.ESXI70000079){
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

# ## Commenting out until this setting does not break vLCM
# ## Execute Approved VIBs
# Try{
# 	$STIGID = "ESXI-70-000080"
# 	$Title = "The ESXi host must only run executables from approved VIBs."
#     If($controlsenabled.ESXI70000080){
#         Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
#         ForEach($vmhost in $vmhosts){
#             $name = $stigsettings.executeVibs.Keys
#             $value = [string]$stigsettings.executeVibs.Values
#             ## Checking to see if current setting exists
#             If($asetting = $vmhost | Get-AdvancedSetting -Name $name -ErrorAction Stop){
#                 If($asetting.value -eq $value){
#                     Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vmhost"
#                     $unchangedcount++
#                 }Else{
#                     Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vmhost...setting to $value"
#                     $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
#                     $changedcount++
#                 }
#             }Else{
#                 Write-ToConsoleYellow "...Setting $name does not exist on $vmhost...creating setting..."
#                 $vmhost | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
#                 $changedcount++
#             }
#         }
#     }
#     Else{
#         Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
#         $skipcount++
#     }
# }
# Catch{
#     Write-ToConsoleRed "Failed to STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
#     Write-ToConsoleRed $_.Exception
#     $failedcount++
# }

## Suppress Hyperthreading Warning
Try{
	$STIGID = "ESXI-70-000081"
	$Title = "The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
    If($controlsenabled.ESXI70000081){
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

# SSH allowtcpforwardning
Try{
	$STIGID = "ESXI-70-000082"
	$Title = "The ESXi host SSH daemon must disable port forwarding."
    If($controlsenabled.ESXI70000082){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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

## SLPD Disabled
Try{
	$STIGID = "ESXI-70-000083"
	$Title = "The ESXi host OpenSLP service must be disabled."
    If($controlsenabled.ESXI70000083){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        $servicename = "slpd"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
            If($vmhostservice.Running -eq $true){
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

## Audit Logging
Try{
	$STIGID = "ESXI-70-000084"
	$Title = "The ESXi host must enable audit logging."
    If($controlsenabled.ESXI70000084){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.auditrecords.get.invoke()
            If($results.AuditRecordStorageActive -eq "true" -and $results.AuditRecordStorageCapacity -eq $stigsettings.auditRecords.size -and $results.AuditRecordStorageDirectory -eq $stigsettings.auditRecords.dir -and $results.AuditRemoteHostEnabled -eq "true"){
                Write-ToConsoleGreen "...Audit Records are enabled correctly on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...Configuring Audit Record logging on $($vmhost.name)"
                $auditargs = $esxcli.system.auditrecords.local.set.CreateArgs()
                #Commenting out directory option since it is configured correctly if not specified. Must exist if specified.
                #$auditargs.directory = $stigsettings.auditRecords.dir
                $auditargs.size="100"
                $esxcli.system.auditrecords.local.set.Invoke($auditargs)
                $esxcli.system.auditrecords.local.enable.Invoke()
                $esxcli.system.auditrecords.remote.enable.Invoke()
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

## Syslog Cert strict x509 verification
Try{
	$STIGID = "ESXI-70-000085"
	$Title = "The ESXi host must enable strict x509 verification for SSL syslog endpoints."
    If($controlsenabled.ESXI70000085){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.syslog.config.get.invoke()
            If($results.StrictX509Compliance -eq "true"){
                Write-ToConsoleGreen "...Syslog x509 strict verification enabled correctly on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...Configuring SSH FipsMode on $($vmhost.name)"
                $syslogargs = $esxcli.system.syslog.config.set.CreateArgs()
                $syslogargs.x509strict = $true
                $esxcli.system.syslog.config.set.Invoke($syslogargs)
                $esxcli.system.syslog.reload.Invoke()
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
	$STIGID = "ESXI-70-000086"
	$Title = "The ESXi host must verify certificates for SSL syslog endpoints."
    If($controlsenabled.ESXI70000086){
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

## Volatile key destruction
Try{
	$STIGID = "ESXI-70-000087"
	$Title = "The ESXi host must enable volatile key destruction."
    If($controlsenabled.ESXI70000087){
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
	$STIGID = "ESXI-70-000088"
	$Title = "The ESXi host must configure a session timeout for the vSphere API."
    If($controlsenabled.ESXI70000088){
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

## Host Client timeout
Try{
	$STIGID = "ESXI-70-000089"
	$Title = "The ESXi Host Client must be configured with a session timeout."
    If($controlsenabled.ESXI70000089){
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

## Rhttpproxy FIPs
Try{
	$STIGID = "ESXI-70-000090"
	$Title = "The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
    If($controlsenabled.ESXI70000090){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.security.fips140.rhttpproxy.get.invoke()
            If($results.Enabled -eq "true"){
                Write-ToConsoleGreen "...SSH FipsMode set correctly to $results on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...Configuring SSH FipsMode on $($vmhost.name)"
                $fipsargs = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
                $fipsargs.enable = $true
                $esxcli.system.security.fips140.rhttpproxy.set.Invoke($fipsargs)
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
	$STIGID = "ESXI-70-000091"
	$Title = "The ESXi host must be configured with an appropriate maximum password age."
    If($controlsenabled.ESXI70000091){
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

# VM Override
Try{
	$STIGID = "ESXI-70-000092"
	$Title = "The ESXi host must not be configured to override virtual machine configurations."
    If($controlsenabled.ESXI70000092){
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
	$STIGID = "ESXI-70-000093"
	$Title = "The ESXi host must not be configured to override virtual machine logger settings."
    If($controlsenabled.ESXI70000093){
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
	$STIGID = "ESXI-70-000094"
	$Title = "The ESXi host must require TPM-based configuration encryption."
    If($controlsenabled.ESXI70000094){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.settings.encryption.get.invoke()
            If($results.Mode -eq "TPM"){
                Write-ToConsoleGreen "...Configuration encryption set correctly to $(results.Mode) on $($vmhost.name)"
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

## Require Secure Boot
Try{
	$STIGID = "ESXI-70-000095"
	$Title = "The ESXi host must implement Secure Boot enforcement."
    If($controlsenabled.ESXI70000095){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.system.settings.encryption.get.invoke()
            If($results.RequireSecureBoot -eq "true"){
                Write-ToConsoleGreen "...Secure Boot required set correctly to $(results.RequireSecureBoot) on $($vmhost.name)"
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

## CIM Disabled
Try{
	$STIGID = "ESXI-70-000097"
	$Title = "The ESXi CIM service must be disabled."
    If($controlsenabled.ESXI70000097){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        $servicename = "CIM Server"
        ForEach($vmhost in $vmhosts){
            $vmhostservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
            If($vmhostservice.Running -eq $true){
                If($stigsettings.cimEnabled -eq $false){
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

## SSH ciphers
Try{
	$STIGID = "ESXI-70-000274"
	$Title = "The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers."
    If($controlsenabled.ESXI70000274){
        Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
        ForEach($vmhost in $vmhosts){
            $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
            $results = $esxcli.software.vib.list.Invoke() | Where-Object {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD} -ErrorAction Stop
            If($results){
                Write-ToConsoleGreen "...VMware STIG VIB is installed on $($vmhost.name)"
                $unchangedcount++
            }Else{
                Write-ToConsoleYellow "...!!VMware STIG VIB is NOT installed on $($vmhost.name) !!"
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
	$STIGID = "ESXI-70-000001"
	$Title = "Access to the ESXi host must be limited by enabling Lockdown Mode."
    If($controlsenabled.ESXI70000001){
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