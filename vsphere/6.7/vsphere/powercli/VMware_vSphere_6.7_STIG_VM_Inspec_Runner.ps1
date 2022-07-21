<# 
.SYNOPSIS 
    Inspec runner for the vSphere 6.7 Virtual Machine STIG
.DESCRIPTION
    -This script assumes there is a vCenter managing the virtual machines
    -This script will iterate through virtual machines found in vCenter and run the Inspec VM STIG profile against them and output results to JSON for each host
    -Also outputs a STIG Viewer Checklist file if inspec_tools exists on the system  https://github.com/mitre/inspec_tools
.NOTES 
    File Name  : VMware_vSphere_6.7_STIG_VM_Inspec_Runner.ps1 
    Author     : Ryan Lakey
    Version    : 1.0

    Tested against
    -PowerCLI 11.3
    -Powershell 5
    -vCenter/ESXi 6.7 U3+
    -Inspec 4.18.51

.PARAMETER vcenter
    Enter the vcenter to connect to for remediation
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,
    HelpMessage="Enter the vCenter FQDN or IP to connect to")]
    [ValidateNotNullOrEmpty()]
    [string]$vcenter,
    [Parameter(Mandatory=$true,
    HelpMessage="Enter the folder path to store reports for example...C:\Inspec\Reports")]
    [ValidateNotNullOrEmpty()]
    [string]$reportPath = "C:\Inspec\Reports",
    [Parameter(Mandatory=$true,
    HelpMessage="Enter the folder path for the Inspec Profile...!!CANNOT HAVE SPACES!!")]
    [ValidateNotNullOrEmpty()]
    [string]$inspecPath
)

#Get Current Date and Time
$date = Get-Date

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
    Exit -1
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
    Exit -1
}

#Get host objects
Try{
    Write-ToConsole "...Getting PowerCLI objects for all virtual machines in vCenter: $vcenter"
    $vms = Get-VM | Sort-Object Name
}
Catch{
    Write-Error "...Failed to get PowerCLI objects"
    Write-Error $_.Exception
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

Write-ToConsole "...Disconnecting from vCenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false

#Verify report folder
Try{
    If(Test-Path -Path $reportPath){
        Write-ToConsole "...Validated path for report at $reportPath"
    }Else{
        Write-ToConsole "...Report path $reportPath doesn't exist...attempting to create..."
        New-Item -ItemType Directory -Path $reportPath -Force -ErrorAction Stop
    }
}
Catch{
    Write-Error "Failed to validate or create specified report directory"
    Write-Error $_.Exception
    Exit -1
}

#Run Inspec profile against all ESXi hosts found
Try{
    ForEach($vm in $vms){
        $name = $vm.Name
        $reportFile = $reportPath + "\VMware_vSphere_6.7_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"
        $command = {inspec exec $inspecPath -t vmware:// --input vmName=$name --show-progress --reporter=json:$reportFile}
        Write-ToConsole "...Report path is $reportPath and report file is $reportFile"
        Write-ToConsole "...Running Inspec exec against $name with $command"
        Invoke-Command -ScriptBlock $command
        If(Get-Command inspec_tools){
            Write-ToConsole "...Detected inspec_tools...generating STIG Viewer Checklist for $name"
            $cklFile = $reportPath + "\VMware_vSphere_6.7_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".ckl"
            $cklCommand = {inspec_tools inspec2ckl -j $reportFile -o $cklFile}
            Invoke-Command -ScriptBlock $cklCommand
        }
    }
}
Catch{
    Write-Error "Failed to run Inspec profile against virtual machines"
    Write-Error $_.Exception
    Exit -1
}
