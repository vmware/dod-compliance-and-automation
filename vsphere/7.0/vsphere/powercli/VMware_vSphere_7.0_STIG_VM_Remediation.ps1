<# 
.SYNOPSIS 
    Remediates virtual machines against the vSphere ESXi 7.0 STIG.
.DESCRIPTION
    -This script assumes there is a vCenter server managing the virtual machines.
    -Please review the $vmsettings below and update as appropriate for your environment
    -This script will NOT remediate attached devices such as floppies, serial/parrallel ports, USB, etc.
.NOTES 
    File Name  : VMware_vSphere_7.0_VM_STIG_Remediation.ps1 
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 12.2
    -Powershell 5
    -vCenter/ESXi 7.0 U1

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
        "isolation.tools.copy.disable" = $true
        "isolation.tools.dnd.disable" = $true
        "isolation.tools.paste.disable" = $true
        "isolation.tools.diskShrink.disable" = $true
        "isolation.tools.diskWiper.disable" = $true
        "isolation.tools.hgfsServerSet.disable" = $true
        "RemoteDisplay.maxConnections" = "1"
        "RemoteDisplay.vnc.enabled" = $false
        "tools.setinfo.sizeLimit" = "1048576"
        "isolation.device.connectable.disable" = $true
        "tools.guestlib.enableHostInfo" = $false
        "tools.guest.desktop.autolock" = $true
        "mks.enable3d" = $false
        "log.rotateSize" = "2048000"
        "log.keepOld" = "10"
    }
    vmAdvSettingsRemove = ("sched.mem.pshare.salt")
    vmotionEncryption = "opportunistic" #disabled, required, opportunistic
    vmLogging = $true
}

#Modules needed to run script and load
$modules = @("VMware.PowerCLI")

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
            Write-ToConsole "...vMotion encryption was incorrectly set to $($vm.extensiondata.Config.MigrateEncryption) on $vm"
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

## Set virtual machine logging
Try{
    ForEach($vm in $vms){
        If($vm.ExtensionData.Config.Flags.EnableLogging -eq $vmconfig.vmLogging){
            Write-ToConsole "...Logging set correctly on $vm to $($vmconfig.vmLogging)"
        }else{
            Write-ToConsole "...Logging was incorrectly set to $($vm.ExtensionData.Config.Flags.EnableLogging) on $vm"
            $vmv = $vm | get-view
            $config = new-object VMware.Vim.VirtualMachineConfigSpec
            $config.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
            $config.Flags.enableLogging = $vmconfig.vmLogging
            $vmv.ReconfigVM($config)
        }
    }
}Catch{
    Write-Error "...Failed to configure virtual machine logging"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit
}

Write-ToConsole "...Disconnecting from vCenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false