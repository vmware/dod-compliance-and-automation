<# 
  .SYNOPSIS 
    The VMware Cloud Foundation vSphere ESX STIG InSpec runner script audits target ESX hosts
    and facilitates creating accreditation artifacts that would require a more manual process
    with InSpec/CINC alone.
  .DESCRIPTION
    The VMware Cloud Foundation vSphere ESX STIG InSpec runner script audits target ESX hosts
    and facilitates creating accreditation artifacts that would require a more manual process
    with InSpec/CINC alone.

    It is designed to connect to a target vCenter server and generate InSpec JSON reports which
    are then converted to STIG Checklist(CKL) files with optionally applied manual attestations
    and relevant STIG metadata.

    The script will output a Powershell transcript as well as the generated artifacts to the
    provided report directory.

  .NOTES 
    File Name  : VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner.ps1 
    Author     : Broadcom
    Version    : 1.0.0
    License    : Apache-2.0

    Minimum Requirements
    
    VCF PowerCLI               : 9.0.0.0
    VMware.VCF.STIG.Helpers    : 1.0.1
    Powershell                 : 5.1
    Powershell Core            : 7.3.4
    vCenter/ESX                : 9.0.x.x
    MITRE SAF CLI              : 1.4.20

  .LINK
    https://github.com/vmware/dod-compliance-and-automation

  .LINK
    https://knowledge.broadcom.com/external/article?legacyId=94398

  .INPUTS
    The VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1 file needs to be updated with the necessary variable values for the target environment prior to running.

    Pipeline input not accepted.

  .OUTPUTS
    Powershell Transcript txt file, InSpec JSON report, and a STIG Checklist file for each target host.

  .PARAMETER vccred
  Enter the pscredential variable name to use for authentication to vCenter. This should be run before the script for example: $cred = Get-Credential
  .PARAMETER NoSafetyChecks
  If specified, this switch parameter will disable "safety" checks to determine supported versions of Powershell modules, vCenter, and ESX are the targets and if not abort the script.
  .PARAMETER GlobalVarsFile
  Global Variables file name. Must be in the same directory as the script.
  .PARAMETER InspecPath
  Full path to the ESX InSpec profile folder.
  .PARAMETER InspecInputsFile
  Full path to the Inspec inputs file to use during the audit.
  .PARAMETER AttestationFile
  Full path to an pre-configured attestation file to use with MITRE's SAF CLI to apply manual attestations to the report artifacts.
  .PARAMETER ProfileName
  To provide the correct metadata for generating CKL files the InSpec profile name is needed and must be exactly as shown in the ESX profiles inspec.yml file. This default value is correct at the time of publication.
  .PARAMETER ReleaseDate
  To provide the correct metadata for generating CKL files the release date as seen in STIG Viewer can be provided.
  .PARAMETER ReleaseNumber
  To provide the correct metadata for generating CKL files the release number as seen in STIG Viewer can be provided.
  .PARAMETER ReleaseVersion
  To provide the correct metadata for generating CKL files the release version as seen in STIG Viewer can be provided.

  .EXAMPLE
  PS> ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -InspecPath /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml

  .EXAMPLE
  PS> ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -NoSafetyChecks -InspecPath /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml

  .EXAMPLE
  PS> ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -InspecPath /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml -AttestationFile VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml

  .EXAMPLE
  PS> ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -InspecPath /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml -AttestationFile VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml -ReleaseDate "02 Jun 2025" -ReleaseNumber "1" -ReleaseVersion "1"
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory=$true,
  HelpMessage="Provide Powershell credential object for use in connecting to the target vCenter server.")]
  [pscredential]$vccred,
  [Parameter(Mandatory=$false,
  HelpMessage="Skip safety checks to verify PowerCLI, vCenter, and ESX versions before running script.")]
  [switch]$NoSafetyChecks = $false,
  [Parameter(Mandatory=$false,
  HelpMessage="Global Variables file name. Must be in the same directory as the script.")]
  [string]$GlobalVarsFile = "VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1",
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the folder path for the InSpec Profile...!!CANNOT HAVE SPACES!!")]
  [ValidateNotNullOrEmpty()]
  [string]$InspecPath,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the full path for the InSpec inputs file.")]
  [ValidateNotNullOrEmpty()]
  [string]$InspecInputsFile,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the full path for the saf cli attestation file.")]
  [ValidateNotNullOrEmpty()]
  [string]$AttestationFile,
  [Parameter(Mandatory=$false,
  HelpMessage="InSpec Profile name to use for providing additional metadata.")]
  [ValidateNotNullOrEmpty()]
  [string]$ProfileName = "VMware Cloud Foundation 9.0 ESX STIG Readiness Guide",
  [Parameter(Mandatory=$false,
  HelpMessage="Release date to use for providing additional metadata. This should match the format in STIG Viewer. For Example: 02 Jun 2025")]
  [ValidateNotNullOrEmpty()]
  [string]$ReleaseDate = "17 Jun 2025",
  [Parameter(Mandatory=$false,
  HelpMessage="Release number to use for providing additional metadata. This should match the format in STIG Viewer. For Example: 1")]
  [ValidateNotNullOrEmpty()]
  [string]$ReleaseNumber = "1",
  [Parameter(Mandatory=$false,
  HelpMessage="Release version to use for providing additional metadata. This should match the format in STIG Viewer. For Example: 1")]
  [ValidateNotNullOrEmpty()]
  [string]$ReleaseVersion = "1"
)

# Script Variables
$STIGVersion = "STIG Readiness Guide Version 1 Release 1"
$ReportNamePrefix = "VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation"
$MinimumPowerCLIVersion = "9.0.0"
$MinimumVCVersion = "9.0.0"
$MaximumVCVersion = "9.0.0"
$MinimumESXVersion = "9.0.0"
$MaximumESXVersion = "9.0.0"
$ReportPrefix = "VMware_Cloud_Foundation_vSphere_ESX_9.x_STIG_InSpec_Report"

# Determine correct directory separate for Windows or Linux
$DirectorySep = [System.IO.Path]::DirectorySeparatorChar

# Import Variables from Global and Remediation variables files
$ScriptPath = (Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path)
$GlobalVariables = $ScriptPath + $DirectorySep + $GlobalVarsFile
Write-Message -Level "INFO" -Message "Importing Global Variables from: $GlobalVariables"
. $GlobalVariables

# Setup reporting and start transcript
Try{
  If($ReportPath){
    # Capture Date variable
    $Date = Get-Date
    # Start Transcript
    $TranscriptName = $ReportPath + $DirectorySep + $ReportNamePrefix + "_Transcript" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".txt"
    Write-Message -Level "INFO" -Message "Starting Powershell Transcript at $TranscriptName"
    Start-Transcript -Path $TranscriptName
  }
  Else{
    Write-Message -Level "ERROR" -Message "No report path specified in $GlobalVariables. Please provide a report path and rerun script."
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to start transcript."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test PowerCLI Version
Try{
  Write-Header -Title "VMware Cloud Foundation ESX STIG Auditing" -STIGVersion $STIGVersion -name $vcenter
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run PowerCLI version check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test PowerCLI Version
Try{
  If($NoSafetyChecks){
    Write-Message -Level "SKIPPED" -Message "No safety check enabled. Skipping PowerCLI version check."
  }
  Else{
    Test-PowerCLI -MinimumPowerCLIVersion $MinimumPowerCLIVersion
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run PowerCLI version check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Connect to vCenter
Try{
  Write-Message -Level "INFO" -Message "Connecting to vCenter: $vcenter"
  Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop | Out-Null
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to connect to vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Test vCenter Version
Try{
  If($NoSafetyChecks){
    Write-Message -Level "SKIPPED" -Message "No safety check enabled. Skipping vCenter version check."
  }
  Else{
    Test-vCenter -MinimumVCVersion $MinimumVCVersion -MaximumVCVersion $MaximumVCVersion
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run vCenter safe check."
  Write-Message -Level "ERROR" -Message  $_.Exception
  Exit -1
}

# Gather Info
Try{
  Write-Message -Level "INFO" -Message "Gathering info on target ESX hosts in vCenter: $vcenter"
  If($hostname){
    $vmhosts = Get-VMHost -Name $hostname -ErrorAction Stop | Sort-Object Name
    ForEach($vmhost in $vmhosts){
      Write-Message -Level "INFO" -Message "Found target host: $($vmhost.name)."
      If($NoSafetyChecks){
        Write-Message -Level "SKIPPED" -Message "No safety checks enabled. Skipping ESX version check on ESX host: $($vmhost.Name)."
      }
      Else{
        Test-ESX -VMHost $vmhost -MinimumESXVersion $MinimumESXVersion -MaximumESXVersion $MaximumESXVersion
      }
    }
  }
  ElseIf($cluster){
    $vmhosts = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object Name
    ForEach($vmhost in $vmhosts){
      Write-Message -Level "INFO" -Message "Found target host: $($vmhost.name)."
      If($NoSafetyChecks){
        Write-Message -Level "SKIPPED" -Message "No safety checks enabled. Skipping ESX version check on ESX host: $($vmhost.Name)."
      }
      Else{
        Test-ESX -VMHost $vmhost -MinimumESXVersion $MinimumESXVersion -MaximumESXVersion $MaximumESXVersion
      }
    }
  }
  Else{
    Write-Message -Level "INFO" -Message "No targets specified for remediation detected in $GlobalVariables. Exiting script."
    Exit
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to gather information on target hosts in vCenter: $vcenter"
  Write-Message -Level "ERROR" -Message $_.Exception
  Write-Message -Level "INFO" -Message "Disconnecting from vCenter Server: $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Write-Message -Level "ERROR" -Message "Stopping Powershell Transcript at $TranscriptName"
  Stop-Transcript
  Exit -1
}

#Run InSpec profile against all ESX hosts found
Try{
  ForEach($vmhost in $vmhosts){
    $name = $vmhost.Name
    $timestamp = "_" + $Date.Year + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second
    $reportFile = $ReportPath + $DirectorySep + $ReportPrefix + "_" + $name + $timestamp + ".json"
    $command = {inspec exec $InspecPath -t vmware:// --input esx_vmhostName=$name esx_cluster="" esx_allHosts=false --input-file $InspecInputsFile --show-progress --enhanced-outcomes --reporter=json:$reportFile}
    Write-Message -Level "INFO" -Message "Report path: $ReportPath and report file: $reportFile"
    Write-Message -Level "INFO" -Message "Running InSpec against ESX host: $name."
    Invoke-Command -ScriptBlock $command
    If(Get-Command saf){
      Write-Message -Level "INFO" -Message "Detected MITRE SAF CLI. Generating STIG Viewer Checklist for ESX host: $name"
      #Get management IP for CKL report
      $mgmtip = Get-VMHostNetworkAdapter -VMHost $vmhost | Where-Object {$_.Name -eq "vmk0"} | Select-Object -ExpandProperty IP
      #Get management MAC Address for CKL report
      $mgmtmac = Get-VMHostNetworkAdapter -VMHost $vmhost | Where-Object {$_.Name -eq "vmk0"} | Select-Object -ExpandProperty Mac
      If($AttestationFile){
        Write-Message -Level "INFO" -Message "Attestation file: $AttestationFile detected. Applying to results for ESX host: $name"
        $reportFileWithAttestations = $ReportPath + $DirectorySep + $ReportPrefix + "_" + $name + "_" + "with_Attestations" + $timestamp + ".json"
        $attestCommand = {saf attest apply -i $reportFile $AttestationFile -o $reportFileWithAttestations}
        Invoke-Command -ScriptBlock $attestCommand
        $cklFile = $ReportPath + $DirectorySep + $ReportPrefix + "_" + $name + "_" + "with_Attestations" + $timestamp + ".ckl"
        Write-Message -Level "INFO" -Message "Generating CKL file: $cklFile with attestations for ESX host: $name"
        $cklCommand = {saf convert hdf2ckl -i $reportFileWithAttestations -o $cklFile --hostname $name --fqdn $name --ip $mgmtip --mac $mgmtmac --profilename "$ProfileName" --releasedate "$ReleaseDate" --releasenumber "$ReleaseNumber" --version "$ReleaseVersion" --vulidmapping "gid"}
        Invoke-Command -ScriptBlock $cklCommand
      }
      Else{
        Write-Message -Level "INFO" -Message "Attestation file not detected. Generating STIG Viewer Checklist for ESX host: $name without attestations."
        $cklFile = $ReportPath + $DirectorySep + $ReportPrefix + "_" + $name + $timestamp + ".ckl"
        Write-Message -Level "INFO" -Message "Generating CKL file: $cklFile for ESX host: $name"
        $cklCommand = {saf convert hdf2ckl -i $reportFile -o $cklFile --hostname $name --fqdn $name --ip $mgmtip --mac $mgmtmac --profilename "$ProfileName" --releasedate "$ReleaseDate" --releasenumber "$ReleaseNumber" --version "$ReleaseVersion" --vulidmapping "gid"}
        Invoke-Command -ScriptBlock $cklCommand
      }
    }
  }
}
Catch{
  Write-Message -Level "ERROR" -Message "Failed to run InSpec profile against hosts"
  Write-Message -Level "ERROR" -Message "Disconnecting from vCenter: $vcenter"
  Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
  Write-Message -Level "ERROR" -Message "Stopping Powershell Transcript at $TranscriptName"
  Stop-Transcript
  Write-Message -Level "ERROR" -Message $_.Exception
  Exit -1
}

Write-Message -Level "INFO" -Message "InSpec Runner Complete"
Write-Message -Level "INFO" -Message "Disconnecting from vCenter: $vcenter"
Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
Write-Message -Level "INFO" -Message "Stopping Powershell Transcript at $TranscriptName"
Stop-Transcript
