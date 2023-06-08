<# 
.SYNOPSIS 
  InSpec runner for the vSphere 7.0 Virual Machine STIG
.DESCRIPTION
  -This script assumes there is a vCenter managing the virtual environment
  -This script will iterate through VMs found in vCenter and run the InSpec VM STIG profile against them and output results to JSON for each VM
  -The environmental variables needed to run the vmware-vsphere-7.0-stig-baseline InSpec baseline must be configured before running this
  -Also outputs a STIG Viewer Checklist file if the saf cli exists on the system. See https://github.com/mitre/saf
  -If an attestation file is supplied it will be applied to the InSpec results before creating the CKL file. This allows you to provide a manual attestation to controls that cannot be audited via automation currently.
  -Example files for environment specific inputs and an attestation file are provided with this script.
.NOTES 
  File Name  : VMware_vSphere_7.0_STIG_VM_InSpec_Runner.ps1 
  Author     : Ryan Lakey
  Version    : 1.0

  Tested against
  -PowerCLI 13
  -Powershell 5.1/Powershell Core 7.3.4
  -vCenter/ESXi 7.0 U3l
  -Inspec 5.22.3
  -SAF CLI 1.2.15

  Example command to run script
    .\VMware_vSphere_7.0_STIG_VM_InSpec_Runner.ps1 -vcenter 10.1.2.3 -reportPath C:\Inspec\Reports\Runner -inspecPath C:\github\dod-compliance-and-automation\vsphere\7.0\vsphere\inspec\vmware-vsphere-7.0-stig-baseline\vm\ -attestationFile C:\github\dod-compliance-and-automation\vsphere\7.0\vsphere\powercli\vmware-vsphere-7.0-stig-esxi-inspec-runner-attestation-example.yml

.PARAMETER vcenter
  Enter the vcenter to connect to and collect hosts to audit.
.PARAMETER reportPath
  Enter the folder path to store reports, for example: C:\InSpec\Reports.
.PARAMETER inspecPath
  Enter the folder path for the InSpec Profile for the vSphere VM 7.0 baseline...!!CANNOT HAVE SPACES!!
.PARAMETER attestationFile
  Enter the path for the saf cli attestation file, for example: C:\github\dod-compliance-and-automation\vsphere\7.0\vsphere\powercli\vmware-vsphere-7.0-stig-esxi-inspec-runner-attestation-example.yml
#>
[CmdletBinding()]
param (
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the vCenter FQDN or IP to connect to")]
  [ValidateNotNullOrEmpty()]
  [string]$vcenter,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the folder path to store reports for example...C:\InSpec\Reports")]
  [ValidateNotNullOrEmpty()]
  [string]$reportPath = "C:\InSpec\Reports",
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the folder path for the InSpec Profile...!!CANNOT HAVE SPACES!!")]
  [ValidateNotNullOrEmpty()]
  [string]$inspecPath,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the saf cli attestation file.")]
  [ValidateNotNullOrEmpty()]
  [string]$attestationFile
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

#Get VM objects
Try{
  Write-ToConsole "...Getting PowerCLI objects for all VMs hosts in vCenter: $vcenter"
  $vms = Get-VM | Sort-Object Name
}
Catch{
  Write-Error "...Failed to get PowerCLI objects"
  Write-Error $_.Exception
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Exit -1
}

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

#Run InSpec profile against all VMs found
Try{
  ForEach($vm in $vms){
    $name = $vm.Name
    $reportFile = $reportPath + "\VMware_vSphere_7.0_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".json"
    $command = {inspec exec $inspecPath -t vmware:// --input vmhostName=$name --show-progress --reporter=json:$reportFile}
    Write-ToConsole "...Report path is $reportPath and report file is $reportFile"
    Write-ToConsole "...Running InSpec exec against $name with $command"
    Invoke-Command -ScriptBlock $command
    If(Get-Command saf){
      Write-ToConsole "...Detected saf cli...generating STIG Viewer Checklist for $name"
      If($attestationFile){
        Write-ToConsole "...Attestion file: $attestationFile detected...applying to results for $name"
        $reportFileWithAttestations = $reportPath + "\VMware_vSphere_7.0_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + "_with_Attestations.json"
        $attestCommand = {saf attest apply -i $reportFile $attestationFile -o $reportFileWithAttestations}
        Invoke-Command -ScriptBlock $attestCommand
        $cklFile = $reportPath + "\VMware_vSphere_7.0_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + "_with_Attestations.ckl"
        $cklCommand = {saf convert hdf2ckl -i $reportFileWithAttestations -o $cklFile --hostname $name --fqdn $name --ip $mgmtip --mac $mgmtmac}
        Invoke-Command -ScriptBlock $cklCommand
      }Else{
        Write-ToConsole "...No attestion file provided for $name"
        $cklFile = $reportPath + "\VMware_vSphere_7.0_STIG_VM_Inspec_Report" + "_" + $name + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".ckl"
        $cklCommand = {saf convert hdf2ckl -i $reportFile -o $cklFile --hostname $name --fqdn $name --ip $mgmtip --mac $mgmtmac}
        Invoke-Command -ScriptBlock $cklCommand
      }
    }
  }
}
Catch{
  Write-Error "Failed to run InSpec profile against VMs"
  Write-Error $_.Exception
  Exit -1
}

Write-ToConsole "...Disconnecting from vCenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
