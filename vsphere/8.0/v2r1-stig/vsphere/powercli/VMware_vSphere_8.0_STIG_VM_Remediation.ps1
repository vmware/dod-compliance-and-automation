<# 
.SYNOPSIS 
  Remediates virtual machines against the vSphere Virtual Machine 8.0 STIG
  Version 2 Release 1
.DESCRIPTION
  -This script assumes there is a vCenter server managing the virtual machines.
  -Please review the $vmsettings below and update as appropriate for your environment
  -This script will NOT remediate the following STIG IDs as they may require the VM to be powered off
    or other environment specific considerations before implementing:
      -VMCH-80-000200
      -VMCH-80-000208
      -VMCH-80-000209
      -VMCH-80-000210
      -VMCH-80-000211
      -VMCH-80-000212
      -VMCH-80-000213
      -VMCH-80-000214

.NOTES 
  File Name  : VMware_vSphere_8.0_VM_STIG_Remediation.ps1 
  Author     : VMware
  Version    : 2.0.1
  License    : Apache-2.0

  Minimum Requirements
  -PowerCLI 13.3
  -Powershell 5.1/Powershell Core 7.3.4
  -vCenter/ESXi 8.0 U3

  Example command to run script
  .\VMware_vSphere_8.0_STIG_VM_Remediation.ps1 -vcenter vcentername.test.local -all myhost.test.local -vccred $cred -reportpath C:\Reports

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
  [Parameter(Mandatory=$true)]
  [pscredential]$vccred,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$virtualmachine,
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$cluster,
  [Parameter(Mandatory=$false,
  HelpMessage="Use -all option to remediate all VMs in target vCenter/ESXi")]
  [ValidateNotNullOrEmpty()]
  [switch]$all=$false,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the output report. Example /tmp")]
  [string]$reportpath
)

$vmconfig = [ordered]@{
  #Hardening/STIG Settings
  vmAdvSettingsMayExist = [ordered]@{
      "isolation.tools.copy.disable" = $true              #VMCH-80-000189
      "isolation.tools.dnd.disable" = $true               #VMCH-80-000191
      "isolation.tools.paste.disable" = $true             #VMCH-80-000192
      "isolation.tools.diskShrink.disable" = $true        #VMCH-80-000193
      "isolation.tools.diskWiper.disable" = $true         #VMCH-80-000194
      "tools.setinfo.sizeLimit" = "1048576"               #VMCH-80-000196
      "isolation.device.connectable.disable" = $true      #VMCH-80-000197
      "tools.guestlib.enableHostInfo" = $false            #VMCH-80-000198
      "tools.guest.desktop.autolock" = $true              #VMCH-80-000201
      "log.rotateSize" = "2048000"                        #VMCH-80-000205
      "log.keepOld" = "10"                                #VMCH-80-000206
  }
  vmAdvSettingsMustExist = [ordered]@{
    "RemoteDisplay.maxConnections" = "1"                #VMCH-80-000195
    "mks.enable3d" = $false                             #VMCH-80-000202
  }
  vmAdvSettingsRemove = ("sched.mem.pshare.salt")         #VMCH-80-000199
  vmotionEncryption = "opportunistic" #disabled, required, opportunistic  #VMCH-80-000203
  ftEncryption = "ftEncryptionOpportunistic"   #ftEncryptionRequired,ftEncryptionOpportunistic #VMCH-80-000204
  vmLogging = $true                                       #VMCH-80-000207
}

#Setup report output
If($reportpath){
    ## Capture Date variable
    $Date = Get-Date
    ## Start Transcript
    $TranscriptName = $reportpath + "\VMware_vSphere_8.0_STIG_VM_Remediation_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
    Start-Transcript -Path $TranscriptName
    ## Results file name for output to json
    $resultjson = $reportpath + "\VMware_vSphere_8.0_STIG_VM_Remediation_Results" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"   
}

##### Setup report variables ####
$changedcount = 0
$unchangedcount= 0
$skipcount = 0
$failedcount = 0

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
    $TranscriptName = $reportpath + "\VMware_vSphere_8.0_STIG_VM_Remediation_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
    Start-Transcript -Path $TranscriptName
    ## Results file name for output to json
    $resultjson = $reportpath + "\VMware_vSphere_8.0_STIG_VM_Remediation_Results" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"   
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

#Connect to vCenter Server
Try
{
    Write-ToConsole "...Connecting to vCenter Server $vcenter"
    Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
}
Catch
{
    Write-ToConsoleRed "Failed to connect to $vcenter"
    Write-ToConsoleRed $_.Exception
    Exit -1
}

#Get host objects
Try
{
    If($all){
        Write-ToConsole "...Getting PowerCLI objects for all virtual machines hosts in vCenter: $vcenter"
        $vms = Get-VM -ErrorAction Stop | Sort-Object Name
    }elseif($cluster) {
        Write-ToConsole "...Getting PowerCLI objects for all virtual machines in cluster: $cluster"
        $vms = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VM -ErrorAction Stop | Sort-Object Name
    }elseif($virtualmachine){
        Write-ToConsole "...Getting PowerCLI object for virtual machine: $virtualmachine"
        $vms = Get-VM -Name $virtualmachine -ErrorAction Stop | Sort-Object Name
    }else{
        Write-ToConsole "...No remediation options specified exiting script"
        Exit
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to get PowerCLI objects"
    Write-ToConsoleRed $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## Remediate Virtual Machine advanced settings that are good by default if they don't exist or if they do must be set to a specific value
Try
{
    ForEach($vm in $vms){
        Write-ToConsole "...Remediating advanced settings on $vm on $vcenter"
        ForEach($setting in ($vmconfig.vmAdvSettingsMayExist.GetEnumerator() | Sort-Object Name)){
        #Pulling values for each setting specified
        $name = $setting.name
        $value = $setting.value
            #Checking to see if current setting exists
            If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
                If($asetting.value -eq $value){
                    Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vm"
                    $unchangedcount++
                }else{
                    Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vm setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
                    $changedcount++
                }
            }else{
                Write-ToConsoleGreen "...Setting $name does not exist on $vm and is compliant by default..."
                $unchangedcount++
            }
        }
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to get set virtual machine advanced settings"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

## Remediate Virtual Machine advanced settings that must exist
Try
{
    ForEach($vm in $vms){
        Write-ToConsole "...Remediating advanced settings on $vm on $vcenter"
        ForEach($setting in ($vmconfig.vmAdvSettingsMustExist.GetEnumerator() | Sort-Object Name)){
        #Pulling values for each setting specified
        $name = $setting.name
        $value = $setting.value
            #Checking to see if current setting exists
            If($asetting = $vm | Get-AdvancedSetting -Name $name -ErrorAction Stop){
                If($asetting.value -eq $value){
                    Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vm"
                    $unchangedcount++
                }else{
                    Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vm setting to $value"
                    $asetting | Set-AdvancedSetting -Value $value -Confirm:$false -ErrorAction Stop
                    $changedcount++
                }
            }else{
              Write-ToConsoleYellow "...Setting $name does not exist on $vm creating setting..."
              $vm | New-AdvancedSetting -Name $name -Value $value -Confirm:$false -ErrorAction Stop
              $changedcount++
            }
        }
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to get set virtual machine advanced settings"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

## Remove advanced settings
Try
{
    ForEach($vm in $vms){
        Write-ToConsole "...Removing advanced settings if necessary on $vm on $vcenter"
        ForEach($setting in ($vmconfig.vmAdvSettingsRemove | Sort-Object Name)){
            #Checking to see if current setting exists
            If($asetting = $vm | Get-AdvancedSetting -Name $setting -ErrorAction Stop){
                Write-ToConsoleYellow "...Setting $setting exists on $vm...removing setting"
                $asetting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop
                $changedcount++
            }
            else{
                Write-ToConsoleGreen "...Setting $setting does not exist on $vm"
                $unchangedcount++
            }
        }   
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to remove virtual machine advanced settings"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

## Set virtual machine vMotion Encryption
Try
{
    ForEach($vm in $vms){
        If($vm.extensiondata.Config.MigrateEncryption -eq $vmconfig.vmotionEncryption){
            Write-ToConsoleGreen "...vMotion encryption set correctly on $vm to $($vmconfig.vmotionEncryption)"
            $unchangedcount++
        }else{
            Write-ToConsoleYellow "...vMotion encryption was incorrectly set to $($vm.extensiondata.Config.MigrateEncryption) on $vm"
            $vmv = $vm | get-view -ErrorAction Stop
            $config = new-object VMware.Vim.VirtualMachineConfigSpec
            $config.MigrateEncryption = New-object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
            $config.MigrateEncryption = "$($vmconfig.vmotionEncryption)"
            $vmv.ReconfigVM($config)
            $changedcount++
        }
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to configure virtual machine vMotion encryption"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

## Set virtual machine ft Encryption
Try
{
    ForEach($vm in $vms){
        If($vm.extensiondata.Config.FtEncryptionMode -eq $vmconfig.ftEncryption){
            Write-ToConsoleGreen "...Fault tolerance encryption set correctly on $vm to $($vmconfig.ftEncryption)"
            $unchangedcount++
        }else{
            Write-ToConsoleYellow "...Fault tolerance encryption was incorrectly set to $($vm.extensiondata.Config.FtEncryptionMode) on $vm"
            $vmv = $vm | Get-View -ErrorAction Stop
            $config = New-Object VMware.Vim.VirtualMachineConfigSpec
            $config.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
            $config.FT = "$($vmconfig.FtEncryptionMode)"
            $vmv.ReconfigVM($config)
            $changedcount++
        }
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to configure virtual machine fault tolerance encryption"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

## Set virtual machine logging
Try
{
    ForEach($vm in $vms){
        If($vm.ExtensionData.Config.Flags.EnableLogging -eq $vmconfig.vmLogging){
            Write-ToConsoleGreen "...Logging set correctly on $vm to $($vmconfig.vmLogging)"
            $unchangedcount++
        }else{
            Write-ToConsoleYellow "...Logging was incorrectly set to $($vm.ExtensionData.Config.Flags.EnableLogging) on $vm"
            $vmv = $vm | get-view -ErrorAction Stop
            $config = new-object VMware.Vim.VirtualMachineConfigSpec
            $config.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
            $config.Flags.enableLogging = $vmconfig.vmLogging
            $vmv.ReconfigVM($config)
            $changedcount++
        }
    }
}
Catch
{
    Write-ToConsoleRed "...Failed to configure virtual machine logging"
    Write-ToConsoleRed $_.Exception
    $failedcount++
}

$summary = New-Object PSObject -Property ([ordered]@{
    "vcenter" = $vcenter
    "vm" = $virtualmachine.Name
    "cluster" = $cluster.Name
    "remediateall" = $all
    "reportpath" = $reportpath
    "ok" = $unchangedcount
    "changed" = $changedcount
    "skipped" = $skipcount
    "failed" = $failedcount
    "inputs" = $vmconfig
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