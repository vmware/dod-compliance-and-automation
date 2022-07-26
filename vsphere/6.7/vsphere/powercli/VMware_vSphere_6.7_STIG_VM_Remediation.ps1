<# 
.SYNOPSIS 
    Remediates virtual machines against the vSphere Virtual Machine 6.7 STIG Version 1 Release 1.
.DESCRIPTION
    -This script assumes there is a vCenter server managing the virtual machines.
    -Please review the $vmsettings below and update as appropriate for your environment
    -This script will NOT remediate the following STIG IDs as they may require the VM to be powered off
     or other environment specific considerations before implementing:
        -VMCH-67-000006
        -VMCH-67-000008
        -VMCH-67-000009
        -VMCH-67-000010
        -VMCH-67-000011
        -VMCH-67-000012
        -VMCH-67-000019
        -VMCH-67-000020
        -VMCH-67-000021
.NOTES 
    File Name  : VMware_vSphere_6.7_VM_STIG_Remediation.ps1 
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.3
    -Powershell 5
    -vCenter/ESXi 6.7 U3+

.PARAMETER vcenter
    Enter the vcenter to connect to for remediation
.PARAMETER all
    Specifying the -all option remediates all virtual machines found in the target vCenter
.PARAMETER cluster
    Specifying the -cluster option only remediates virtual machines in the target vCenter and specified cluster
.PARAMETER virtualmachine
    Specifying the -vm option will only remediate the target virtual machine
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,
    HelpMessage="Enter the vCenter/ESXi FQDN or IP to connect to")]
    [ValidateNotNullOrEmpty()]
    [string]$vcenter,
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$virtualmachine,
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$cluster,
    [Parameter(Mandatory=$false,
    HelpMessage="Use -all option to remediate all VMs in target vCenter/ESXi")]
    [ValidateNotNullOrEmpty()]
    [switch]$all=$false
)

$vmconfig = @{
    #Hardening/STIG Settings
    vmAdvSettings = @{
        "isolation.tools.copy.disable" = $true              #VMCH-67-000001
        "isolation.tools.dnd.disable" = $true               #VMCH-67-000002
        "isolation.tools.paste.disable" = $true             #VMCH-67-000003
        "isolation.tools.diskShrink.disable" = $true        #VMCH-67-000004
        "isolation.tools.diskWiper.disable" = $true         #VMCH-67-000005
        "isolation.tools.hgfsServerSet.disable" = $true     #VMCH-67-000007
        "RemoteDisplay.maxConnections" = "1"                #VMCH-67-000013
        "RemoteDisplay.vnc.enabled" = $false                #VMCH-67-000014
        "tools.setinfo.sizeLimit" = "1048576"               #VMCH-67-000015
        "isolation.device.connectable.disable" = $true      #VMCH-67-000016
        "tools.guestlib.enableHostInfo" = $false            #VMCH-67-000017
        "tools.guest.desktop.autolock" = $true              #VMCH-67-000022
        "mks.enable3d" = $false                             #VMCH-67-000023
    }
    vmAdvSettingsRemove = ("sched.mem.pshare.salt")         #VMCH-67-000018
    vmotionEncryption = "opportunistic"                     #VMCH-67-000024 disabled, required, opportunistic
}

#Modules needed to run script and load
$modules = @("VMware.VimAutomation.Core")

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

#Get Credentials for vCenter
Write-ToConsole "...Enter credentials to connect to vCenter"
$vccred = Get-Credential -Message "Enter credentials for vCenter"

#Connect to vCenter Server
Try
{
    Write-ToConsole "...Connecting to vCenter Server $vcenter"
    Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
}
Catch
{
    Write-Error "Failed to connect to $vcenter"
    Write-Error $_.Exception
    Exit
}

#Get host objects
Try{
    If($all){
        Write-ToConsole "...Getting PowerCLI objects for all virtual machines hosts in vCenter: $vcenter"
        $vms = Get-VM | Sort-Object Name
    }elseif($cluster) {
        Write-ToConsole "...Getting PowerCLI objects for all virtual machines in cluster: $cluster"
        $vms = Get-Cluster -Name $cluster | Get-VM | Sort-Object Name
    }elseif($virtualmachine){
        Write-ToConsole "...Getting PowerCLI object for virtual machine: $virtualmachine"
        $vms = Get-VM -Name $virtualmachine | Sort-Object Name
    }else{
        Write-ToConsole "...No remediation options specified exiting script"
        Exit
    }
}
Catch{
    Write-Error "...Failed to get PowerCLI objects"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit
}

## Remediate Virtual Machine advanced settings
Try{
    ForEach($vm in $vms){
        Write-ToConsole "...Remediating advanced settings on $vm on $vcenter"
            ForEach($setting in ($vmconfig.vmAdvSettings.GetEnumerator() | Sort-Object Name)){
            #Pulling values for each setting specified
            $name = $setting.name
            $value = $setting.value
                #Checking to see if current setting exists
                If($asetting = $vm | Get-AdvancedSetting -Name $name){
                    If($asetting.value -eq $value){
                    Write-ToConsole "...Setting $name is already configured correctly to $value on $vm"
                    }else{
                        Write-ToConsole "...Setting $name was incorrectly set to $($asetting.value) on $vm setting to $value"
                        $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
                    }
                }else{
                    Write-ToConsole "...Setting $name does not exist on $vm creating setting..."
                    $vm | New-AdvancedSetting -Name $name -Value $value -Confirm:$false
                }
            }
    }
}Catch{
    Write-Error "...Failed to get set virtual machine advanced settings"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit
}

## Remove advanced settings
Try{
    ForEach($vm in $vms){
        Write-ToConsole "...Removing advanced settings if necessary on $vm on $vcenter"
            ForEach($setting in ($vmconfig.vmAdvSettingsRemove | Sort-Object Name)){
                #Checking to see if current setting exists
                If($asetting = $vm | Get-AdvancedSetting -Name $setting){
                    Write-ToConsole "...Setting $setting exists on $vm...removing setting"
                    $asetting | Remove-AdvancedSetting -Confirm:$false
                }
                else{
                    Write-ToConsole "...Setting $setting does not exist on $vm"
                }
            }   
    }
}Catch{
    Write-Error "...Failed to remove virtual machine advanced settings"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit
}

## Set virtual machine vMotion Encryption
Try{
    ForEach($vm in $vms){
        If($vm.extensiondata.Config.MigrateEncryption -eq $vmconfig.vmotionEncryption){
            Write-ToConsole "...vMotion encryption set correctly on $vm to $($vmconfig.vmotionEncryption)"
        }else{
            $vmv = $vm | get-view
            $config = new-object VMware.Vim.VirtualMachineConfigSpec
            $config.MigrateEncryption = New-object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
            $config.MigrateEncryption = "$($vmconfig.vmotionEncryption)"
            $vmv.ReconfigVM($config)
        }
    }
}Catch{
    Write-Error "...Failed to configure virtual machine vMotion encryption"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit
}

Write-ToConsole "...Disconnecting from vCenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false