<# 
.SYNOPSIS 
    Remediates vCenter Server against the draft vSphere vCenter 7.0 STIG.
.DESCRIPTION
    -Please review the $vcconfig below and update as appropriate for your environment
    -VCSA-70-000016 is disabled by default. Configure a NetFlow collector IP below if needed or leave blank and enable control to remove NetFlow configuration and disable on all port groups.

.NOTES 
    File Name  : VMware_vSphere_7.0_vCenter_STIG_Remediation.ps1 
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.3
    -Vmware.Vsphere.SsoAdmin 1.3.2
    -Powershell 5.1+
    -vCenter U1d

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
    [securestring]$ssopass
)

$vcconfig = @{
    ssoPasswordReuse     = "5" #VCSA-70-000001
    ssoPasswordLifetime  = "60" #VCSA-70-000003
    ssoPasswordLength    = "15" #VCSA-70-000039
    ssoPasswordUpper     = "1" #VCSA-70-000040
    ssoPasswordLower     = "1" #VCSA-70-000041
    ssoPasswordNum       = "1" #VCSA-70-000042
    ssoPasswordSpecial   = "1" #VCSA-70-000043
    ssoLoginAttempts     = "3" #VCSA-70-000045
    ssoFailureInterval   = "900" #VCSA-70-000046
    ssoUnlockTime        = "0" #VCSA-70-000047
    vpxdExpiration       = @{"VirtualCenter.VimPasswordExpirationInDays" = "30"} #VCSA-70-000023
    vpxdPwLength         = @{"config.vpxd.hostPasswordLength" = "32"} #VCSA-70-000024
    configLogLevel       = @{"config.log.level" = "info"} #VCSA-70-000036
    vcNetflowCollectorIp = ""
    bashAdminUsers       = @("Administrator") #VCSA-70-000070  Administrator is the only user or group by default in this group
    bashAdminGroups      = @()  #VCSA-70-000070
    trustedAdminUsers    = @() #VCSA-70-000071  No users or groups by default
    trustedAdminGroups   = @()  #VCSA-70-000071
    vpxdEventSyslog      = @{"vpxd.event.syslog.enabled" = "true"} #VCSA-70-000075
    dbEventAge           = @{"event.maxAge" = "30"} #VCSA-70-000078
    dbTaskAge            = @{"task.maxAge" = "30"} #VCSA-70-000078
}

##### Enable or Disable specific STIG Remediations #####
$VCSA70000001 = $true  #SSO Password Reuse
$VCSA70000003 = $true  #SSO Password Lifetime
$VCSA70000004 = $true  #Client session timeout
$VCSA70000005 = $true  #vCenter Role Assignment
$VCSA70000007 = $true  #NIOC
$VCSA70000009 = $true  #AD Auth
$VCSA70000012 = $true  #DVS Health Check
$VCSA70000013 = $true  #Reject forged transmits
$VCSA70000014 = $true  #Reject MAC changes
$VCSA70000015 = $true  #Reject promiscious mode
$VCSA70000016 = $false  #Net Flow
$VCSA70000016disablepgs = $false  #Disable NetFlow on all port groups since you may want it enabled
$VCSA70000018 = $true  #Native VLAN
$VCSA70000019 = $true  #VLAN Trunking
$VCSA70000020 = $true  #Reserved VLANs
$VCSA70000023 = $true  #VPXD PW
$VCSA70000024 = $true  #VPXD PW Length
$VCSA70000031 = $true  #LCM Isolation
$VCSA70000034 = $true  #Service Accounts
$VCSA70000035 = $true  #Plugins
$VCSA70000036 = $true  #Log Level
$VCSA70000039 = $true  #SSO Password Length
$VCSA70000040 = $true  #SSO Password Upper
$VCSA70000041 = $true  #SSO Password Lower
$VCSA70000042 = $true  #SSO Password Numeric
$VCSA70000043 = $true  #SSO Password Special
$VCSA70000045 = $true  #SSO Login Attempts
$VCSA70000046 = $true  #SSO Failure Interval
$VCSA70000047 = $true  #SSO Unlock Time
$VCSA70000052 = $true  #Storage Isolation
$VCSA70000054 = $true  #vSAN Health Check
$VCSA70000055 = $true  #vSAN Datastore Name
$VCSA70000057 = $true  #TLS 1.2
$VCSA70000058 = $true  #DoD Certs
$VCSA70000059 = $true  #CAC Auth
$VCSA70000060 = $true  #Cert Revocation
$VCSA70000061 = $true  #Disable UN/PW
$VCSA70000062 = $true  #Login Banner
$VCSA70000063 = $true  #Crypto Role
$VCSA70000064 = $true  #Crypto Permissions
$VCSA70000065 = $true  #vSAN iSCSI CHAP
$VCSA70000066 = $true  #vSAN Rekey
$VCSA70000067 = $true  #CEIP
$VCSA70000068 = $true  #LDAPS
$VCSA70000069 = $true  #LDAP Service Account
$VCSA70000070 = $true  #Bash Admin Group
$VCSA70000071 = $true  #Trusted Admin Group
$VCSA70000072 = $true  #Syslog Server
$VCSA70000073 = $true  #User Mgmt Alerts
$VCSA70000074 = $true  #Backups
$VCSA70000075 = $true  #Syslog Events
$VCSA70000076 = $true  #SNMP v2
$VCSA70000077 = $true  #SNMP v3
$VCSA70000078 = $true  #Task Retention
$VCSA70000079 = $true  #Native Key Provider


#Modules needed to run script and load
$modules = @("VMware.PowerCLI","VMware.Vsphere.SsoAdmin")

#Check for correct modules
Function checkModule ($m){
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        Write-Host "Module $m is already imported."
    }
    else{
        Write-Host "Trying to import module $m"
        Import-Module $m -Verbose
    }
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

#Load Modules
Try
{
    ForEach($module in $modules){
        checkModule $module
    }
}
Catch
{
    Write-Error "Failed to load modules"
    Write-Error $_.Exception
    Exit
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
    Exit
}

## SSO Password Reuse
Try{
    $STIGID = "VCSA-70-000001"
    $Title = "The vCenter Server must prohibit password reuse for a minimum of five generations."
    If($VCSA70000001){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.ProhibitedPreviousPasswordsCount -ne $vcconfig.ssoPasswordReuse){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -ProhibitedPreviousPasswordsCount $vcconfig.ssoPasswordReuse
        }Else{
            Write-ToConsoleGreen "...SSO password reuse set to $($vcconfig.ssoPasswordReuse) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Lifetime
Try{
    $STIGID = "VCSA-70-000003"
    $Title = "The vCenter Server must enforce a 60-day maximum password lifetime restriction."
    If($VCSA70000003){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.PasswordLifetimeDays -ne $vcconfig.ssoPasswordLifetime){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -PasswordLifetimeDays $vcconfig.ssoPasswordLifetime
        }Else{
            Write-ToConsoleGreen "...SSO password lifetime set to $($vcconfig.ssoPasswordLifetime) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Client session timeout
Try{
    $STIGID = "VCSA-70-000004"
    $Title = "The vCenter Server must terminate vSphere Client sessions after 10 minutes of inactivity."
    If($VCSA70000004){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## vCenter Role Assignment
Try{
    $STIGID = "VCSA-70-000005"
    $Title = "The vCenter Server users must have the correct roles assigned."
    If($VCSA70000005){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## NIOC
Try{
    $STIGID = "VCSA-70-000007"
    $Title = "The vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC)."
    If($VCSA70000007){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                If($switch.ExtensionData.Config.NetworkResourceManagementEnabled -eq $false){
                    Write-ToConsoleRed "...Network IO Control not enabled on $($switch.name) on $vcenter"
                    ($switch | Get-View).EnableNetworkResourceManagement($true)
                }Else{
                    Write-ToConsoleGreen "...Network IO Control enabled on $($switch.name) on $vcenter"
                }
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## AD Auth
Try{
    $STIGID = "VCSA-70-000009"
    $Title = "The vCenter Server must implement Active Directory authentication."
    If($VCSA70000009){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## DVS Health Check
Try{
    $STIGID = "VCSA-70-000012"
    $Title = "The vCenter Server must disable the distributed virtual switch health check."
    If($VCSA70000012){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                If($switch.ExtensionData.Config.HealthCheckConfig.Enable[0] -eq $true -or $switch.ExtensionData.Config.HealthCheckConfig.Enable[1] -eq $true){
                    Write-ToConsoleRed "...Health check enabled on $($switch.name) on $vcenter"
                    ($switch | Get-View).UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))
                }Else{
                    Write-ToConsoleGreen "...Health check disabled on $($switch.name) on $vcenter"
                }
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Reject forged transmits
Try{
    $STIGID = "VCSA-70-000013"
    $Title = "The vCenter Server must set the distributed port group Forged Transmits policy to reject."
    If($VCSA70000013){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                $policy = $switch | Get-VDSecurityPolicy
                If($policy.ForgedTransmits -eq $true){
                    Write-ToConsoleRed "...Forged Transmits enabled on $($switch.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -ForgedTransmits $false
                }Else{
                    Write-ToConsoleGreen "...Forged Transmits disabled on $($switch.name) on $vcenter"
                }
            }
            ForEach($pg in $dvpg){
                $policy = $pg | Get-VDSecurityPolicy
                If($policy.ForgedTransmits -eq $true){
                    Write-ToConsoleRed "...Forged Transmits enabled on $($pg.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -ForgedTransmits $false
                }Else{
                    Write-ToConsoleGreen "...Forged Transmits disabled on $($pg.name) on $vcenter"
                }
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## MacChanges
Try{
    $STIGID = "VCSA-70-000014"
    $Title = "The vCenter Server must set the distributed port group MAC Address Change policy to reject."
    If($VCSA70000014){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                $policy = $switch | Get-VDSecurityPolicy
                If($policy.MacChanges -eq $true){
                    Write-ToConsoleRed "...MAC Changes enabled on $($switch.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -MacChanges $false
                }Else{
                    Write-ToConsoleGreen "...MAC Changes disabled on $($switch.name) on $vcenter"
                }
            }
            ForEach($pg in $dvpg){
                $policy = $pg | Get-VDSecurityPolicy
                If($policy.MacChanges -eq $true){
                    Write-ToConsoleRed "...MAC Changes enabled on $($pg.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -MacChanges $false
                }Else{
                    Write-ToConsoleGreen "...MAC Changes disabled on $($pg.name) on $vcenter"
                }
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## promiscious mode
Try{
    $STIGID = "VCSA-70-000015"
    $Title = "The vCenter Server must set the distributed port group Promiscuous Mode policy to reject."
    If($VCSA70000015){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                $policy = $switch | Get-VDSecurityPolicy
                If($policy.AllowPromiscuous -eq $true){
                    Write-ToConsoleRed "...Promiscious Mode enabled on $($switch.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
                }Else{
                    Write-ToConsoleGreen "...Promiscious Mode disabled on $($switch.name) on $vcenter"
                }
            }
            ForEach($pg in $dvpg){
                $policy = $pg | Get-VDSecurityPolicy
                If($policy.AllowPromiscuous -eq $true){
                    Write-ToConsoleRed "...Promiscious Mode enabled on $($pg.name) on $vcenter"
                    $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
                }Else{
                    Write-ToConsoleGreen "...Promiscious Mode disabled on $($pg.name) on $vcenter"
                }
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Net Flow
Try{
    $STIGID = "VCSA-70-000016"
    $Title = "The vCenter Server must only send NetFlow traffic to authorized collectors."
    If($VCSA70000016){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        If($dvs.count -eq 0){
            Write-ToConsoleGreen "...No distributed switches detected on $vcenter"
        }Else{
            ForEach($switch in $dvs){
                If($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress -ne $vcconfig.vcNetflowCollectorIp){
                    Write-ToConsoleRed "...Unknown NetFlow collector on $($switch.name) on $vcenter"
                    $switchview = $switch | Get-View
                    $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
                    $spec.configversion = $switchview.Config.ConfigVersion
                    $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
                    $spec.IpfixConfig.CollectorIpAddress = ""
                    $spec.IpfixConfig.CollectorPort = "0"
                    $spec.IpfixConfig.ObservationDomainId = "0"
                    $spec.IpfixConfig.ActiveFlowTimeout = "60"
                    $spec.IpfixConfig.IdleFlowTimeout = "15"
                    $spec.IpfixConfig.SamplingRate = "4096"
                    $spec.IpfixConfig.InternalFlowsOnly = $False
                    $switchview.ReconfigureDvs_Task($spec)
                }Else{
                    Write-ToConsoleGreen "...No unknown NetFlow collectors configured on $($switch.name) on $vcenter"
                }
            }
            If($VCSA70000016disablepgs){
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
                    }Else{
                        Write-ToConsoleGreen "...NetFlow collection disabled on $($pg.name) on $vcenter"
                    }
                }   
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Native VLAN
Try{
    $STIGID = "VCSA-70-000018"
    $Title = "The vCenter Server must configure all port groups to a value other than that of the native VLAN."
    If($VCSA70000018){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## VLAN Trunking
Try{
    $STIGID = "VCSA-70-000019"
    $Title = "The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized."
    If($VCSA70000019){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Reserved VLANs
Try{
    $STIGID = "VCSA-70-000020"
    $Title = "The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches."
    If($VCSA70000020){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## VPXD PW
Try{
    $STIGID = "VCSA-70-000023"
    $Title = "The vCenter Server must configure the vpxuser auto-password to be changed every 30 days."
    If($VCSA70000023){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $name = $vcconfig.vpxdExpiration.Keys
        $value = [string]$vcconfig.vpxdExpiration.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsole "...Setting $name does not exist on $vcenter...creating setting..."
            New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## VPXD PW Length
Try{
    $STIGID = "VCSA-70-000024"
    $Title = "The vCenter Server must configure the vpxuser password meets length policy."
    If($VCSA70000024){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $name = $vcconfig.vpxdPwLength.Keys
        $value = [string]$vcconfig.vpxdPwLength.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsoleGreen "...Setting $name does not exist on $vcenter and is not a finding..."
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## LCM Isolation
Try{
    $STIGID = "VCSA-70-000031"
    $Title = "The vCenter Server must be isolated from the public Internet but must still allow for patch notification and delivery."
    If($VCSA70000031){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Service Accounts
Try{
    $STIGID = "VCSA-70-000034"
    $Title = "The vCenter Server must use unique service accounts when applications connect to vCenter."
    If($VCSA70000034){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Plugins
Try{
    $STIGID = "VCSA-70-000035"
    $Title = "vCenter Server plugins must be verified."
    If($VCSA70000035){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually and is not currently supported in PowerCLI!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Log Level
Try{
    $STIGID = "VCSA-70-000036"
    $Title = "The vCenter Server must produce audit records containing information to establish what type of events occurred."
    If($VCSA70000036){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $name = $vcconfig.configLogLevel.Keys
        $value = [string]$vcconfig.configLogLevel.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsole "...Setting $name does not exist on $vcenter...creating setting..."
            New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Length
Try{
    $STIGID = "VCSA-70-000039"
    $Title = "The vCenter Server passwords must be at least 15 characters in length."
    If($VCSA70000039){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.MinLength -ne $vcconfig.ssoPasswordLength){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -MinLength $vcconfig.ssoPasswordLength
        }Else{
            Write-ToConsoleGreen "...SSO password length set to $($vcconfig.ssoPasswordLength) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Upper
Try{
    $STIGID = "VCSA-70-000040"
    $Title = "The vCenter Server passwords must contain at least one uppercase character."
    If($VCSA70000040){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.MinUppercaseCount -ne $vcconfig.ssoPasswordUpper){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -MinUppercaseCount $vcconfig.ssoPasswordUpper
        }Else{
            Write-ToConsoleGreen "...SSO min upper characters set to $($vcconfig.ssoPasswordUpper) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Lower
Try{
    $STIGID = "VCSA-70-000041"
    $Title = "The vCenter Server passwords must contain at least one lowercase character."
    If($VCSA70000041){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.MinLowercaseCount -ne $vcconfig.ssoPasswordLower){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -MinLowercaseCount $vcconfig.ssoPasswordLower
        }Else{
            Write-ToConsoleGreen "...SSO min lower characters set to $($vcconfig.ssoPasswordLower) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Numeric
Try{
    $STIGID = "VCSA-70-000042"
    $Title = "The vCenter Server passwords must contain at least one numeric character."
    If($VCSA70000042){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.MinNumericCount -ne $vcconfig.ssoPasswordNum){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -MinNumericCount $vcconfig.ssoPasswordNum
        }Else{
            Write-ToConsoleGreen "...SSO min numeric characters set to $($vcconfig.ssoPasswordNum) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Password Special
Try{
    $STIGID = "VCSA-70-000043"
    $Title = "The vCenter Server passwords must contain at least one special character."
    If($VCSA70000043){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssopwpolicies = Get-SsoPasswordPolicy
        If($ssopwpolicies.MinSpecialCharCount -ne $vcconfig.ssoPasswordSpecial){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssopwpolicies | Set-SsoPasswordPolicy -MinSpecialCharCount $vcconfig.ssoPasswordSpecial
        }Else{
            Write-ToConsoleGreen "...SSO password min special characters set to $($vcconfig.ssoPasswordSpecial) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Login Attempts
Try{
    $STIGID = "VCSA-70-000045"
    $Title = "The vCenter Server must limit the maximum number of failed login attempts to three."
    If($VCSA70000045){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssolockpolicies = Get-SsoLockoutPolicy
        If($ssolockpolicies.MaxFailedAttempts -ne $vcconfig.ssoLoginAttempts){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssolockpolicies | Set-SsoLockoutPolicy -MaxFailedAttempts $vcconfig.ssoLoginAttempts
        }Else{
            Write-ToConsoleGreen "...SSO login attempts set to $($vcconfig.ssoLoginAttempts) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Failure Interval
Try{
    $STIGID = "VCSA-70-000046"
    $Title = "The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes."
    If($VCSA70000046){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssolockpolicies = Get-SsoLockoutPolicy
        If($ssolockpolicies.FailedAttemptIntervalSec -ne $vcconfig.ssoFailureInterval){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssolockpolicies | Set-SsoLockoutPolicy -FailedAttemptIntervalSec $vcconfig.ssoFailureInterval
        }Else{
            Write-ToConsoleGreen "...SSO failed login interval set to $($vcconfig.ssoFailureInterval) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SSO Unlock Time
Try{
    $STIGID = "VCSA-70-000047"
    $Title = "The vCenter Server must require an administrator to unlock an account locked due to excessive login failures."
    If($VCSA70000047){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $ssolockpolicies = Get-SsoLockoutPolicy
        If($ssolockpolicies.AutoUnlockIntervalSec -ne $vcconfig.ssoUnlockTime){
            Write-ToConsoleRed "...SSO password reuse set incorrectly on $vcenter"
            $ssolockpolicies | Set-SsoLockoutPolicy -AutoUnlockIntervalSec $vcconfig.ssoUnlockTime
        }Else{
            Write-ToConsoleGreen "...SSO unlock interval set to $($vcconfig.ssoUnlockTime) on $vcenter"
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Storage Isolation
Try{
    $STIGID = "VCSA-70-000052"
    $Title = "The vCenter Server must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
    If($VCSA70000052){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## vSAN Health Check
Try{
    $STIGID = "VCSA-70-000054"
    $Title = "The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server."
    If($VCSA70000054){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## vSAN Datastore Name
Try{
    $STIGID = "VCSA-70-000055"
    $Title = "The vCenter Server must configure the vSAN Datastore name to a unique name."
    If($VCSA70000055){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## TLS 1.2
Try{
    $STIGID = "VCSA-70-000057"
    $Title = "The vCenter Server must enable TLS 1.2 exclusively."
    If($VCSA70000057){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## DoD Certs
Try{
    $STIGID = "VCSA-70-000058"
    $Title = "The vCenter Server Machine SSL certificate must be issued by a DoD certificate authority."
    If($VCSA70000058){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## CAC
Try{
    $STIGID = "VCSA-70-000059"
    $Title = "The vCenter Server must enable certificate based authentication."
    If($VCSA70000059){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Cert Revocation
Try{
    $STIGID = "VCSA-70-000060"
    $Title = "The vCenter Server must enable revocation checking for certificate based authentication."
    If($VCSA70000060){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Disable UN/PW
Try{
    $STIGID = "VCSA-70-000061"
    $Title = "The vCenter Server must disable Username/Password and Windows Integrated Authentication."
    If($VCSA70000061){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Login Banner
Try{
    $STIGID = "VCSA-70-000062"
    $Title = "The vCenter Server must enable the login banner for vSphere Client."
    If($VCSA70000062){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Crypto Role
Try{
    $STIGID = "VCSA-70-000063"
    $Title = "The vCenter Server must restrict access to the cryptographic role."
    If($VCSA70000063){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Crypto Permissions
Try{
    $STIGID = "VCSA-70-000064"
    $Title = "The vCenter Server must restrict access to cryptographic permissions."
    If($VCSA70000064){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## vSAN iSCSI CHAP
Try{
    $STIGID = "VCSA-70-000065"
    $Title = "The vCenter Server must have Mutual CHAP configured for vSAN iSCSI targets."
    If($VCSA70000065){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## vSAN Rekey
Try{
    $STIGID = "VCSA-70-000066"
    $Title = "The vCenter Server must have new Key Encryption Keys (KEKs) re-issued at regular intervals for vSAN encrypted datastore(s)."
    If($VCSA70000066){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## CEIP
Try{
    $STIGID = "VCSA-70-000067"
    $Title = "The vCenter Server must disable the Customer Experience Improvement Program (CEIP)."
    If($VCSA70000067){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## LDAPS
Try{
    $STIGID = "VCSA-70-000068"
    $Title = "The vCenter Server must use LDAPS when adding an LDAP identity source."
    If($VCSA70000068){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## LDAP Service Account
Try{
    $STIGID = "VCSA-70-000069"
    $Title = "The vCenter Server must use a limited privilege account when adding an LDAP identity source."
    If($VCSA70000069){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Bash Admin Group
Try{
    $STIGID = "VCSA-70-000070"
    $Title = "The vCenter Server must limit membership to the SystemConfiguration.BashShellAdministrators SSO group."
    If($VCSA70000070){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $groupname = "SystemConfiguration.BashShellAdministrators"
        $users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
        $groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
        ForEach($user in $users){
            If($vcconfig.bashAdminUsers.Contains($user.name)){
                Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
            }Else{
                Write-ToConsoleRed "...User: $($user.name) in not approved...removing..."
                Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
            }
        }
        ForEach($group in $groups){
            If($vcconfig.bashAdminGroups.Contains($group.name)){
                Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
            }Else{
                Write-ToConsoleRed "...Group: $($group.name) in not approved...removing..."
                Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Trusted Admin Group
Try{
    $STIGID = "VCSA-70-000071"
    $Title = "The vCenter Server must limit membership to the TrustedAdmins SSO group."
    If($VCSA70000071){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $groupname = "TrustedAdmins"
        $users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
        $groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
        ForEach($user in $users){
            If($vcconfig.trustedAdminUsers.Contains($user.name)){
                Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
            }Else{
                Write-ToConsoleRed "...User: $($user.name) in not approved...removing..."
                Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
            }
        }
        ForEach($group in $groups){
            If($vcconfig.trustedAdminGroups.Contains($group.name)){
                Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
            }Else{
                Write-ToConsoleRed "...Group: $($group.name) in not approved...removing..."
                Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
            }
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Syslog Server
Try{
    $STIGID = "VCSA-70-000072"
    $Title = "The vCenter Server must be configured to send logs to a central log server."
    If($VCSA70000072){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## User Mgmt Alerts
Try{
    $STIGID = "VCSA-70-000073"
    $Title = "The vCenter Server must provide an immediate real-time alert to the SA and ISSO, at a minimum, on every SSO account action."
    If($VCSA70000073){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Backups
Try{
    $STIGID = "VCSA-70-000074"
    $Title = "The vCenter server configuration must be backed up on a regular basis."
    If($VCSA70000074){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Send events to syslog
Try{
    $STIGID = "VCSA-70-000075"
    $Title = "The vCenter server must be configured to send events to a central log server."
    If($VCSA70000075){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $name = $vcconfig.vpxdEventSyslog.Keys
        $value = [string]$vcconfig.vpxdEventSyslog.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsole "...Setting $name does not exist on $vcenter...creating setting..."
            New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SNMP v2
Try{
    $STIGID = "VCSA-70-000076"
    $Title = "The vCenter server must disable SNMPv1/2 receivers."
    If($VCSA70000076){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## SNMP v3
Try{
    $STIGID = "VCSA-70-000077"
    $Title = "The vCenter server must enforce SNMPv3 security features where SNMP is required."
    If($VCSA70000077){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Task Retention
Try{
    $STIGID = "VCSA-70-000078"
    $Title = "vCenter task and event retention must be set to at least 30 days."
    If($VCSA70000078){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        $name = $vcconfig.dbEventAge.Keys
        $value = [string]$vcconfig.dbEventAge.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsole "...Setting $name does not exist on $vcenter...creating setting..."
            New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        }
        $name = $vcconfig.dbTaskAge.Keys
        $value = [string]$vcconfig.dbTaskAge.Values
        ## Checking to see if current setting exists
        If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
            If($asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
            }Else{
                Write-ToConsoleRed "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
                $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
            }
        }Else{
            Write-ToConsole "...Setting $name does not exist on $vcenter...creating setting..."
            New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
        }
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Native Key Provider
Try{
    $STIGID = "VCSA-70-000079"
    $Title = "vCenter Native Key Providers must be backed up with a strong passsword."
    If($VCSA70000079){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

## Native Key Provider
Try{
    $STIGID = "VCSA-70-000079"
    $Title = "vCenter Native Key Providers must be backed up with a strong passsword."
    If($VCSA70000079){
        Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
        Write-ToConsoleRed "...!!This control must be remediated manually!!"
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to remediate STIG ID: $STIGID with Title: $Title on $vcenter"
    Write-Error $_.Exception
    Write-ToConsoleRed "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Disconnect-SsoAdminServer -Server $vcenter
    Exit -1
}

Write-ToConsoleGreen "...End of script...Disconnecting from vCenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
Disconnect-SsoAdminServer -Server $vcenter