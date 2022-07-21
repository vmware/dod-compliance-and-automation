<# 
.SYNOPSIS 
    Generates HTML Report to audit compliance against the vSphere 6.7 Version 1 Release 1 STIG.
.DESCRIPTION
    -This does not remediate any controls.
    -Not all controls can be checked programatically so this script does not cover those or policy type controls.
    -Controls and be disabled by updating the Vulnerability ID to $false   For example $V94569 = $false.  These are all listed out at the top of the script.
.NOTES 
    File Name  : VMware_vSphere_6.7_STIG_Compliance_Report.ps1
    Author     : Ryan Lakey
    Version    : 1.0
    License    : Apache-2.0

    Tested against
    -PowerCLI 11.3
    -Powershell 5
    -ESXi 6.7 U3+
.PARAMETER vcenter
    Enter the vcenter fqdn or IP to connect to for auditing
.PARAMETER vccred
    Generate and pass a powershell credential variable to this parameter.  For example $cred = Get-Credential  then do "-vccred $cred" when running the script
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$vcenter,
    [Parameter(Mandatory=$true)]
    [pscredential]$vccred,
    [Parameter(Mandatory=$false,
    HelpMessage="Must be the root account credentials at this time.  For checking items that require direct access on the host.")]
    [pscredential]$esxicred,
    [Parameter(Mandatory=$false,
    HelpMessage="Enter the Active Directory Admins group to use for administrative access to ESXi")]
    [string]$esxAdminGroup="SG-ESXAdmins",
    [Parameter(Mandatory=$false,
    HelpMessage="Enter allowed IP ranges for the ESXi firewall in comma separated format.  For Example `"192.168.0.0/16`",`"10.0.0.0/8`" ")]
    [string[]]$allowedNetworks,
    [Parameter(Mandatory=$false,
    HelpMessage="Enter allowed IP addresses for the ESXi firewall in comma separated format.  For Example `"192.168.0.1`",`"10.0.0.1`" ")]
    [string[]]$allowedIPs,
    [Parameter(Mandatory=$false,
    HelpMessage="Enter the syslog server for the ESXi server(s). Example tcp://log.domain.local:514")]
    [string]$syslogServer="tcp://log.domain.local:514",
    [Parameter(Mandatory=$true,
    HelpMessage="Enter NTP servers.  For Example `"10.1.1.1`",`"10.1.1.2`" ")]
    [string[]]$ntpServers,
    [Parameter(Mandatory=$false,
    HelpMessage="Specify the native VLAN Id configured on the ports going to the ESXi Hosts.  If none is specified the default of 1 will be used.")]
    [string]$nativeVLAN = "1"
)

#Get Current Date and Time
$date = Get-Date

#Report Name
$ReportName = "vSphere 6.7 DISA STIG Version 1 Release 1 Compliance Report"

#Report Path - move to parameter later
$ReportOutputPath = "C:\PowerCLI\Output"
$ReportFile = $ReportOutputPath + "\VMware_vSphere_6.7_STIG_Compliance_Report" + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + "_" + $Date.Hour + "-" + $Date.Minute + "-" + $Date.Second + ".html"

#HTML Report Options
##Tabs to generate for report
$tabarray = @('Overview','Virtual Machines','ESXi','vCenter')

#Logo Files
[String]$CompanyLogo = "https://www.vmware.com/content/dam/digitalmarketing/vmware/en/files/images/wmrc/VMware_logo_gry_RGB_72dpi.jpg"
[String]$RightLogo = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm32Zwz84atzMO6bpguQkTLwCEIrOoPUpfrptbkCGMkiMiCtav"

#vSphere 6.7 STIG Settings   Created this up here to make it easier to update settings and values in the future without digging for them down in the code
$stigsettings = @{
    ##### Environment Specific STIG Values #####
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}
    stigVibRE               = "dod-esxi67-stig-re"   #Update with STIG VIB version used
    stigVibRD               = "dod-esxi67-stig-rd"   #Update with STIG VIB version used
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup}
    allowedNetworks         = $allowedNetworks #@("10.0.0.0/8","192.168.0.0/16")  #Allows IP ranges for the ESXi firewall.  These should be in the same order as seen in the UI.
    allowedIPs              = $allowedIPs  #@()  #Allows IP addresses if any for the ESXi firewall.  These should be in the same order as seen in the UI.
    ntpServers              = $ntpServers  #@("10.1.1.1","10.1.1.2")
    esxiLatestBuild         = "14320388"
    nativeVLANid            = $nativeVLAN  #"1"
    adDomain                = "corp.local"
    certAuthName            = "O=U.S. Government"  #certificate authority issuer name  For example "O=U.S. Government"
    ## ESXi
    DCUIAccess              = @{"DCUI.Access" = "root"}
    vibacceptlevel          = "PartnerSupported"  #VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"}
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"}
    logLevel                = @{"Config.HostAgent.log.level" = "info"}
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false}
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "120"}
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"}
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "120"}
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"}
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"}
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""}
    syslogScratch           = @{"Syslog.global.logDir" = "[] /scratch/log"}
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"}
    passHistory             = @{"Security.PasswordHistory" = "5"}
    passComplexity          = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"}
    banner                  = @{"Config.Etc.issue" = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."}
    SuppressShellWarning    = @{"UserVars.SuppressShellWarning" = 0}
    ## Virtual Machines
    vmIsoCopyDisable        = @{"isolation.tools.copy.disable" = $true}
    vmIsoDndDisable         = @{"isolation.tools.dnd.disable" = $true}
    vmIsoPasteDisable       = @{"isolation.tools.paste.disable" = $true}
    vmIsoDiskShrink         = @{"isolation.tools.diskShrink.disable" = $true}
    vmIsoDiskWiper          = @{"isolation.tools.diskWiper.disable" = $true}
    vmIsoHgfsDisable        = @{"isolation.tools.hgfsServerSet.disable" = $true}
    vmRemoteMax             = @{"RemoteDisplay.maxConnections" = 1}
    vmRemoteVnc             = @{"RemoteDisplay.vnc.enabled" = $false}
    vmToolsInfoSize         = @{"tools.setinfo.sizeLimit" = 1048576}
    vmDevConnDisable        = @{"isolation.device.connectable.disable" = $true}
    vmEnableHostInfo        = @{"tools.guestlib.enableHostInfo" = $false}
    vmGuestLock             = @{"tools.guest.desktop.autolock" = $true}
    vmMks3D                 = @{"mks.enable3d" = $false}
    ## vCenter
    vcLogLevel              = @{"config.log.level" = "info"}
}

##### Enable or Disable specific STIG Remediations #####
#Virtual Machines
$V239332 = $true #isolation.tools.copy.disable V94563 VMCH-67-000001	
$V239333 = $true #isolation.tools.dnd.disable V94565 VMCH-67-000002
$V239334 = $true #isolation.tools.paste.disable V94569 VMCH-67-000003
$V239335 = $true #isolation.tools.diskShrink.disable V94571 VMCH-67-000004
$V239336 = $true #isolation.tools.diskWiper.disable V94573 VMCH-67-000005
$V239337 = $true #Independent, non-persistent disks V94575 VMCH-67-000006	
$V239338 = $true #isolation.tools.hgfsServerSet.disable V94577 VMCH-67-000007
$V239339 = $true #Unauthorized floppy devices V94613 VMCH-67-000008
$V239340 = $true #Unauthorized CD/DVD devices V94615 VMCH-67-000009
$V239341 = $true #Unauthorized parallel devices V94617 VMCH-67-000010
$V239342 = $true #Unauthorized serial devices V94619 VMCH-67-000011
$V239343 = $true #Unauthorized USB devices V94621 VMCH-67-000012
$V239344 = $true #Console connection sharing V94623 VMCH-67-000013
$V239345 = $true #Console access through the VNC protocol must be disabled V94625 VMCH-67-000014
$V239346 = $true #tools.setinfo.sizeLimit V94627 VMCH-67-000015
$V239347 = $true #isolation.device.connectable.disable V94629 VMCH-67-000016
$V239348 = $true #tools.guestlib.enableHostInfo V94631 VMCH-67-000017
$V239349 = $true #sched.mem.pshare.salt V94633 VMCH-67-000018
$V239350 = $true #"ethernet*.filter*.name*" V94635 VMCH-67-000019
$V239351 = $true #System administrators must use templates to deploy virtual machines whenever possible. V94637 VMCH-67-000020
$V239352 = $true #Use of the virtual machine console must be minimized. V94639 VMCH-67-000021
$V239353 = $true #tools.guest.desktop.autolock V94641 VMCH-67-000022
$V239354 = $true #mks.enable3d V94643 VMCH-67-000023
$V242469 = $true #vMotion Encryption V94645 VMCH-67-000024

#ESXi
$V239258 = $true  #Lockdown Mode V93949 ESXI-67-000001
$V239259 = $true  #DCUI.Access List V93951 ESXI-67-000002
$V239260 = $true  #Lockdown Mode Exceptions V93953 ESXI-67-000003
$V239261 = $true  #Syslog V93955 ESXI-67-000004
$V239262 = $true  #Account Lock Failures V93957 ESXI-67-000005
$V239263 = $true  #Account Unlock Timeout V93959 ESXI-67-000006
$V239264 = $true  #Consent Banner Welcome V93961 ESXI-67-000007
$V239265 = $true  #Consent Banner /etc/issue V93963 ESXI-67-000008
$V239266 = $true  #SSH Banner V93965 ESXI-67-000009
$V239267 = $true  #SSH Ciphers aes128-ctr,aes192-ctr,aes256-ctr V93967 ESXI-67-000010
#$V93969 = $true  #SSH Protocol 2 V93969 ESXI-67-000011 #Removed
$V239268 = $true  #SSH IgnoreRhosts yes V93971 ESXI-67-000012
$V239269 = $true  #SSH HostbasedAuthentication no V93973 ESXI-67-000013
$V239270 = $true  #SSH PermitRootLogin no V93975 ESXI-67-000014
$V239271 = $true  #SSH PermitEmptyPasswords no V93977 ESXI-67-000015
$V239272 = $true  #SSH PermitUserEnvironment no V93979 ESXI-67-000016
#$V93981 = $true  #SSH MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512 V93981 #Removed
$V239273 = $true  #SSH GSSAPIAuthentication no V93983 ESXI-67-000018
$V239274 = $true  #SSH KerberosAuthentication no V93985 ESXI-67-000019
$V239275 = $true  #SSH StrictModes yes V93987 ESXI-67-000020
$V239276 = $true  #SSH Compression no V93989 ESXI-67-000021
$V239277 = $true  #SSH GatewayPorts no V93991 ESXI-67-000022
$V239278 = $true  #SSH X11Forwarding no V93993 ESXI-67-000023
$V239279 = $true  #SSH AcceptEnv no V93995 ESXI-67-000024
$V239280 = $true  #SSH PermitTunnel no V93997 ESXI-67-000025
$V239281 = $true  #SSH ClientAliveCountMax 3 V93999 ESXI-67-000026
$V239282 = $true  #SSH ClientAliveInterval 200 V94001 ESXI-67-000027
$V239283 = $true  #SSH MaxSessions 1 V94003 ESXI-67-000028
$V239284 = $true  #Authorized Keys V94005 ESXI-67-000029
$V239285 = $true  #Log Level V94007 ESXI-67-000030
$V239286 = $true  #Password Complexity V94009 ESXI-67-000031
$V239287 = $true  #Password Reuse V94011 ESXI-67-000032
$V239288 = $true  #Password Hashes V94013 ESXI-67-000033
$V239289 = $true  #Mob V94015 ESXI-67-000034
$V239290 = $true  #SSH Running V94017 ESXI-67-000035
$V239291 = $true  #disable ESXi Shell V94019 ESXI-67-000036
$V239292 = $true  #Active Directory V94021 ESXI-67-000037
$V239293 = $true  #Authentication Proxy V94023 ESXI-67-000038
$V239294 = $true  #AD Admin Group V94025 ESXI-67-000039
$V239295 = $false  #2FA multifactor authentication for local DCUI access V94027 ESXI-67-000040_________________________________________________________________________
$V239296 = $true  #Shell Interactive Timeout V94029 ESXI-67-000041
$V239297 = $true  #Shell Timeout V94031 ESXI-67-000042
$V239298 = $true  #DCUI Timeout V94033 ESXI-67-000043
$V239299 = $true  #Core Dumps V94035 ESXI-67-000044
$V239300 = $true  #Persistent Logs V94037 ESXI-67-000045
$V239301 = $true  #NTP V94039 ESXI-67-000046
$V239302 = $true #Acceptance Level V94041 ESXI-67-000047
$V239303 = $true  #Isolate vMotion V94043 ESXI-67-000048
$V239304 = $true  #Protect Management V94045 ESXI-67-000049
$V239305 = $true  #Protect Storage traffic V94047 ESXI-67-000050
#$V94049 = $true  #VMK Separation #Removed from 6.7
$V239306 = $true  #TCP/IP Stacks V94051 ESXI-67-000052
$V239307 = $true  #SNMP V94053 ESXI-67-000053
$V239308 = $true  #iSCSI CHAP V94055 ESXI-67-000054
$V239309 = $true  #Memory Salting V94057 ESXI-67-000055
$V239310 = $true  #Firewall Rules V94059 ESXI-67-000056
$V239311 = $true  #Default Firewall V94061 ESXI-67-000057
$V239312 = $true  #BPDU V94063 ESXI-67-000058
$V239313 = $true  #Forged Transmits V94065 ESXI-67-000059
$V239314 = $true  #MAC Changes V94067 ESXI-67-000060
$V239315 = $true  #Prom Mode V94069 ESXI-67-000061
$V239316 = $true  #dvFilter V94071 ESXI-67-000062
$V239317 = $true  #Native VLAN V94073 ESXI-67-000063
$V239318 = $true  #VLAN 4095 V94075 ESXI-67-000064
$V239319 = $true  #Reserved VLANs V94077 ESXI-67-000065
$V239320 = $true  #DTP V94079 ESXI-67-000066
$V239321 = $true  #STP V94081 ESXI-67-000067
$V239322 = $true  #Required VLANs V94083 ESXI-67-000068
$V239323 = $true  #CIM Account V94349 ESXI-67-000070
$V239324 = $true  #Checksum V94477 ESXI-67-000071
$V239325 = $true  #Patch Level V94479 ESXI-67-000072
#Removed from 6.7 $V94481 = $true  #TLS 1.2 SFCB
$V239326 = $true  #TLS 1.2 ipFilter vSAN V94483 ESXI-67-000074
#Removed from 6.7 $V94485 = $true  #TLS 1.2 authd 
$V239327 = $true  #Secureboot V94487 ESXI-67-000076
$V239328 = $true  #DoD Cert V94489 ESXI-67-000078
$V239329 = $true  #host must not suppress warnings ESXI-67-000079 NEW
$V239330 = $true  #central log host ESXI-67-100004 NEW
$V239331 = $true  #FIPS-approved ciphers ESXI-67-100010 NEW

#vCenter
$V94725 = $true  #Permissions
$V94727 = $true  #NIOC
$V94735 = $true  #DVS Healthcheck
$V94737 = $true  #Forged Transmits
$V94739 = $true  #Mac Changes
$V94741 = $true  #Promiscious Mode
$V94743 = $true  #Netflow
$V94745 = $true  #Port level settings
$V94747 = $true  #native vlan
$V94749 = $true  #trunk
$V94751 = $true  #reserved vlans
$V94753 = $true  #
$V94755 = $true  #
$V94781 = $true  #log level



#Modules needed to run script and load
$modules = @("VMware.VimAutomation.Core","ReportHTML")

#Check for correct modules
Function checkModule ($m){
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        Write-ToConsole "...Module $m is already imported."
    }
    else{
        Write-ToConsole "...Trying to import module $m"
        Import-Module $m -Verbose
    }
}

Function Test-WebServerSSL {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
            [string]$URL,
            [Parameter(Position = 1)]
            [ValidateRange(1,65535)]
            [int]$Port = 443,
            [Parameter(Position = 2)]
            [Net.WebProxy]$Proxy,
            [Parameter(Position = 3)]
            [int]$Timeout = 15000,
            [switch]$UseUserContext
        )
    Add-Type @"
    using System;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    namespace PKI {
        namespace Web {
            public class WebSSL {
                public Uri OriginalURi;
                public Uri ReturnedURi;
                public X509Certificate2 Certificate;
                //public X500DistinguishedName Issuer;
                //public X500DistinguishedName Subject;
                public string Issuer;
                public string Subject;
                public string[] SubjectAlternativeNames;
                public bool CertificateIsValid;
                //public X509ChainStatus[] ErrorInformation;
                public string[] ErrorInformation;
                public HttpWebResponse Response;
            }
        }
    }
"@
    $ConnectString = "https://$url`:$port"
    $WebRequest = [Net.WebRequest]::Create($ConnectString)
    $WebRequest.Proxy = $Proxy
    $WebRequest.Credentials = $null
    $WebRequest.Timeout = $Timeout
    $WebRequest.AllowAutoRedirect = $true
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    try {$Response = $WebRequest.GetResponse()}
    catch {}
    if ($WebRequest.ServicePoint.Certificate -ne $null) {
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
        catch {$SAN = $null}
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
        $Status = $chain.Build($Cert)
        New-Object PKI.Web.WebSSL -Property @{
            OriginalUri = $ConnectString;
            ReturnedUri = $Response.ResponseUri;
            Certificate = $WebRequest.ServicePoint.Certificate;
            Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
            Subject = $WebRequest.ServicePoint.Certificate.Subject;
            SubjectAlternativeNames = $SAN;
            CertificateIsValid = $Status;
            Response = $Response;
            ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
        }
        $chain.Reset()
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } else {
        Write-Error $Error[0]
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

#Add type to trust all certificates during checks otherwise some items will fail
If(-not [System.Net.ServicePointManager].DeclaredProperties | Where {$_.name -eq "CertificatePolicy"}){
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
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

#Test report path
Try
{
    If(Test-Path -Path $ReportOutputPath){
        Write-ToConsole "...Validated path for report at $ReportOutputPath"
    }Else{
        Write-ToConsole "...Report path $ReportOutputPath doesn't exist...attempting to create..."
        New-Item -ItemType Directory -Path $ReportOutputPath -Force -ErrorAction Stop
    }
}
Catch
{
    Write-Error "Failed to validate or create specified report directory"
    Write-Error $_.Exception
    Exit -1
}

#Connect to vCenter
Try
{
    Write-ToConsole "...Connecting to vCenter $vcenter"
    Connect-VIServer -Server $vcenter -Credential $vccred -Protocol https -ErrorAction Stop
}
Catch
{
    Write-Error "Failed to connect to $vcenter"
    Write-Error $_.Exception
    Exit -1
}

#Initiate Variables
$report = @()

#Gather vCenter, ESXi, and VM Info
Try
{
    Write-ToConsole "...Gathering info on target hosts in $vcenter"
    $vmhosts = Get-VMHost | Where {$_.version -match "^6.7*"} | Where {$_.connectionstate -ne "Disconnected" } | Where {$_.connectionstate -ne "NotResponding" }|  Sort-Object -Property Name -ErrorAction Stop
    $vmhostsv = $vmhosts | Get-View | Sort-Object -Property Name -ErrorAction Stop
    Write-ToConsole "...Gathering info on target virtual machines in $vcenter"
    $vms = Get-VM | Sort-Object -Property Name -ErrorAction Stop
    $vmsv = $vms | Get-View | Sort-Object -Property Name -ErrorAction Stop
    Write-ToConsole "...Gathering info on $vcenter"
    $datastores = Get-Datastore | Sort-Object -Property Name -ErrorAction Stop
    $clusters = Get-Cluster | Sort-Object -Property Name -ErrorAction Stop
    $vdswitches = Get-VDSwitch | Sort-Object -Property Name -ErrorAction Stop
    $dportgroups = Get-VDPortGroup | Where {$_.IsUplink -eq $false} | Sort-Object -Property Name -ErrorAction Stop
}
Catch
{
    Write-Error "Failed to gather info on environment in $vcenter"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

#Virtual Machine Processing
#Initialize array for all VM report data
$vmsarrayall = @()

## VMCH-67-000001
Try{
    $VULID = "V-239332"
    $STIGID = "VMCH-67-000001"
    $Title = "Copy operations must be disabled on the virtual machine."
    $Severity = "CAT III"
    If($V239332){
        $vmtitle01 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoCopyDisable.Keys
        $settingvalue = [string]$stigSettings.vmIsoCopyDisable.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray01 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000002
Try{
    $VULID = "V-239333"
    $STIGID = "VMCH-67-000002"
    $Title = "Drag and drop operations must be disabled on the virtual machine."
    $Severity = "CAT III"
    If($V239333){
        $vmtitle02 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoDndDisable.Keys
        $settingvalue = [string]$stigSettings.vmIsoDndDisable.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray02 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000003
Try{
    $VULID = "V-239334"
    $STIGID = "VMCH-67-000003"
    $Title = "Paste operations must be disabled on the virtual machine."
    $Severity = "CAT III"
    If($V239334){
        $vmtitle03 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoPasteDisable.Keys
        $settingvalue = [string]$stigSettings.vmIsoPasteDisable.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray03 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000004
Try{
    $VULID = "V-239335"
    $STIGID = "VMCH-67-000004"
    $Title = "Virtual disk shrinking must be disabled on the virtual machine."
    $Severity = "CAT II"
    If($V239335){
        $vmtitle04 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoDiskShrink.Keys
        $settingvalue = [string]$stigSettings.vmIsoDiskShrink.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray04 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000005
Try{
    $VULID = "V-239336"
    $STIGID = "VMCH-67-000005"
    $Title = "Virtual disk erasure must be disabled on the virtual machine."
    $Severity = "CAT II"
    If($V239336){
        $vmtitle05 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoDiskWiper.Keys
        $settingvalue = [string]$stigSettings.vmIsoDiskWiper.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray05 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000006
Try{
    $VULID = "V-239337"
    $STIGID = "VMCH-67-000006"
    $Title = "Independent, non-persistent disks must be not be used on the virtual machine."
    $Severity = "CAT II"
    If($V239337){
        $vmtitle06 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vminddisks = $vm | Get-HardDisk | Where {$_.Persistence -eq "IndependentNonPersistent"}
            If($vminddisks){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vminddisks.count) independent non-persistent disks"
                    "Expected" = "Indepenent non-persistent disks do not exist"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vminddisks.count) independent non-persistent disks"
                    "Expected" = "Indepenent non-persistent disks do not exist"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray06 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000007
Try{
    $VULID = "V-239338"
    $STIGID = "VMCH-67-000007"
    $Title = "HGFS file transfers must be disabled on the virtual machine."
    $Severity = "CAT II"
    If($V239338){
        $vmtitle07 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmIsoHgfsDisable.Keys
        $settingvalue = [string]$stigSettings.vmIsoHgfsDisable.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray07 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000008
Try{
    $VULID = "V-239339"
    $STIGID = "VMCH-67-000008"
    $Title = "Unauthorized floppy devices must be disconnected on the virtual machine."
    $Severity = "CAT II"
    If($V239339){
        $vmtitle08 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vmfloppys = $vm | Get-FloppyDrive
            If($vmfloppys){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmfloppys.count) floppy drives"
                    "Expected" = "Floppy drives do not exist"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmfloppys.count) floppy drives"
                    "Expected" = "Floppy drives do not exist"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray08 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000009
Try{
    $VULID = "V-239340"
    $STIGID = "VMCH-67-000009"
    $Title = "Unauthorized CD/DVD devices must be disconnected on the virtual machine."
    $Severity = "CAT III"
    If($V239340){
        $vmtitle09 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vmcds = $vm | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true}
            If($vmcds){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmcds.count) CD/DVD drives connected"
                    "Expected" = "CD/DVD drives are not connected when not in use"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmcds.count) CD/DVD drives connected"
                    "Expected" = "CD/DVD drives are not connected when not in use"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray09 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000010
Try{
    $VULID = "V-239341"
    $STIGID = "VMCH-67-000010"
    $Title = "Unauthorized parallel devices must be disconnected on the virtual machine."
    $Severity = "CAT II"
    If($V239341){
        $vmtitle10 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vmparrallel = $vm.config.hardware.device.deviceinfo | Where {$_.Label -match "parallel"}
            If($vmparrallel){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmparrallel.count) parrallel devices connected"
                    "Expected" = "Parrallel devices do not exist"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmparrallel.count) parrallel devices connected"
                    "Expected" = "Parrallel devices do not exist"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray10 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000011
Try{
    $VULID = "V-239342"
    $STIGID = "VMCH-67-000011"
    $Title = "Unauthorized serial devices must be disconnected on the virtual machine."
    $Severity = "CAT II"
    If($V239342){
        $vmtitle11 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vmserial = $vm.config.hardware.device.deviceinfo | Where {$_.Label -match "serial"}
            If($vmserial){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmserial.count) serial devices connected"
                    "Expected" = "Serial devices do not exist"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmserial.count) serial devices connected"
                    "Expected" = "Serial devices do not exist"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray11 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000012
Try{
    $VULID = "V-239343"
    $STIGID = "VMCH-67-000012"
    $Title = "Unauthorized USB devices must be disconnected on the virtual machine."
    $Severity = "CAT II"
    If($V239343){
        $vmtitle12 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"
            $vmusb = $vm.config.hardware.device.deviceinfo | Where {$_.Label -match "USB con*"}
            If($vmusb){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmusb.count) USB Controllers attached"
                    "Expected" = "USB controllers do not exist except where needed to attach Smart Card readers"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Found" = "VM has $($vmusb.count) USB Controllers attached"
                    "Expected" = "USB controllers do not exist except where needed to attach Smart Card readers"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray12 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000013
Try{
    $VULID = "V-239344"
    $STIGID = "VMCH-67-000013"
    $Title = "Console connection sharing must be limited on the virtual machine."
    $Severity = "CAT II"
    If($V239344){
        $vmtitle13 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmRemoteMax.Keys
        $settingvalue = [string]$stigSettings.vmRemoteMax.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray13 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000014
Try{
    $VULID = "V-239345"
    $STIGID = "VMCH-67-000014"
    $Title = "Console access through the VNC protocol must be disabled on the virtual machine."
    $Severity = "CAT II"
    If($V239345){
        $vmtitle14 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmRemoteVnc.Keys
        $settingvalue = [string]$stigSettings.vmRemoteVnc.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray14 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000015
Try{
    $VULID = "V-239346"
    $STIGID = "VMCH-67-000015"
    $Title = "Informational messages from the virtual machine to the VMX file must be limited on the virtual machine."
    $Severity = "CAT III"
    If($V239346){
        $vmtitle15 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmToolsInfoSize.Keys
        $settingvalue = [string]$stigSettings.vmToolsInfoSize.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray15 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000016
Try{
    $VULID = "V-239347"
    $STIGID = "VMCH-67-000016"
    $Title = "Unauthorized removal, connection and modification of devices must be prevented on the virtual machine."
    $Severity = "CAT II"
    If($V239347){
        $vmtitle16 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmDevConnDisable.Keys
        $settingvalue = [string]$stigSettings.vmDevConnDisable.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray16 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000017
Try{
    $VULID = "V-239348"
    $STIGID = "VMCH-67-000017"
    $Title = "The virtual machine must not be able to obtain host information from the hypervisor."
    $Severity = "CAT II"
    If($V239348){
        $vmtitle17 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmEnableHostInfo.Keys
        $settingvalue = [string]$stigSettings.vmEnableHostInfo.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray17 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000018
Try{
    $VULID = "V-239349"
    $STIGID = "VMCH-67-000018"
    $Title = "Shared salt values must be disabled on the virtual machine."
    $Severity = "CAT III"
    If($V239349){
        $vmtitle18 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = "sched.mem.pshare.salt"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $currentvalue.key
                    "Value" = $currentvalue.value
                    "Expected" = "Setting does not exist on VM"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = "Setting does not exist on VM"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray18 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000019
Try{
    $VULID = "V-239350"
    $STIGID = "VMCH-67-000019"
    $Title = "Access to virtual machines through the dvfilter network APIs must be controlled."
    $Severity = "CAT III"
    If($V239350){
        $vmtitle19 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = "ethernet*.filter*.name"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            $dvFilters = $vm.config.extraconfig | where {$_.key -like $settingname}            
            If($dvFilters){
                $currentvalue = $vm.config.extraconfig | where {$_.key -like $settingname}
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $currentvalue.key
                    "Value" = $currentvalue.value
                    "Expected" = "Setting does not exist on VM if dvFilters are not in use"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = "Setting does not exist on VM if dvFilters are not in use"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray19 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000022
Try{
    $VULID = "V-239353"
    $STIGID = "VMCH-67-000022"
    $Title = "The virtual machine guest operating system must be locked when the last console connection is closed."
    $Severity = "CAT II"
    If($V239353){
        $vmtitle22 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmGuestLock.Keys
        $settingvalue = [string]$stigSettings.vmGuestLock.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Compliant" = $false
                })
            }
        }
        $vmsarray22 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000023
Try{
    $VULID = "V-239354"
    $STIGID = "VMCH-67-000023"
    $Title = "3D features on the virtual machine must be disabled when not required."
    $Severity = "CAT III"
    If($V239354){
        $vmtitle23 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.vmMks3D.Keys
        $settingvalue = [string]$stigSettings.vmMks3D.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vmsv){
            Write-ToConsole "...Checking VM $($vm.Name) for $settingname"
            If($vm.config.extraconfig.key -contains "$settingname"){
                $currentvalue = $vm.config.extraconfig | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $vmsarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vm.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vm.config.extraconfig.key -notcontains "$settingname"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on VM"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vmsarray23 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VMCH-67-000024
Try{
    $VULID = "V-242469"
    $STIGID = "VMCH-67-000024"
    $Title = "Encryption must be enabled for vMotion on the virtual machine."
    $Severity = "CAT II"
    If($V242469){
        $vmtitle24 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $vmsarray = @()
        ForEach($vm in $vms){
            Write-ToConsole "...Checking VM $($vm.Name) for $title"        
            If($vm.extensiondata.Config.MigrateEncryption -eq "disabled"){
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = "vMotion Encryption"
                    "Value" = $vm.extensiondata.Config.MigrateEncryption
                    "Expected" = "Required or Opportunistic"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vmsarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vm.name
                    "Setting" = "vMotion Encryption"
                    "Value" = $vm.extensiondata.Config.MigrateEncryption
                    "Expected" = "Required or Opportunistic"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vmsarray24 = Set-TableRowColor -ArrayOfObjects $vmsarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmsarrayall += $vmsarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vm.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

#End Virtual Machine Processing

#ESXi Processing
#Initialize array for all ESXi report data
$vmhostsarrayall = @()

## ESXI-67-000001
Try{
    $VULID = "V-239258"
    $STIGID = "ESXI-67-000001"
    $Title = "The ESXi host must limit the number of concurrent sessions to ten for all accounts and/or account types by enabling lockdown mode."
    $Severity = "CAT II"
    If($V239258){
        $esxititle01 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            If($vmhost.config.LockdownMode -eq "lockdownDisabled"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Lockdown Mode"
                    "Value" = $vmhost.config.LockdownMode
                    "Expected" = "lockdownNormal or lockdownStrict"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Lockdown Mode"
                    "Value" = $vmhost.config.LockdownMode
                    "Expected" = "lockdownNormal or lockdownStrict"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray01 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000002
Try{
    $VULID = "V-239259"
    $STIGID = "ESXI-67-000002"
    $Title = "The ESXi host must verify the DCUI.Access list."
    $Severity = "CAT III"
    If($V239259){
        $esxititle02 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigSettings.DCUIAccess.Keys
        $settingvalue = [string]$stigsettings.DCUIAccess.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray02 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000003
Try{
    $VULID = "V-239260"
    $STIGID = "ESXI-67-000003"
    $Title = "The ESXi host must verify the exception users list for lockdown mode."
    $Severity = "CAT III"
    If($V239260){
        $esxititle03 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
            $exceptions = $lockdown.QueryLockdownExceptions()             
            If($exceptions){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Lockdown Mode Exceptions"
                    "Value" = &{If($exceptions){([String]::Join(',',$exceptions))}else{"No users found."}}
                    "Expected" = "No exception users found or are documented"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Lockdown Mode Exceptions"
                    "Value" = &{If($exceptions){([String]::Join(',',$exceptions))}else{"No users found."}}
                    "Expected" = "No exception users found or are documented"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray03 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000004
Try{
    $VULID = "V-239261"
    $STIGID = "ESXI-67-000004"
    $Title = "Remote logging for ESXi hosts must be configured."
    $Severity = "CAT II"
    If($V239261){
        $esxititle04 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigsettings.syslogHost.Keys
        $settingvalue = [string]$stigsettings.syslogHost.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray04 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000005
Try{
    $VULID = "V-239262"
    $STIGID = "ESXI-67-000005"
    $Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
    $Severity = "CAT II"
    If($V239262){
        $esxititle05 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigsettings.accountLockFailures.Keys
        $settingvalue = [string]$stigsettings.accountLockFailures.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray05 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000006
Try{
    $VULID = "V-239263"
    $STIGID = "ESXI-67-000006"
    $Title = "The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out."
    $Severity = "CAT II"
    If($V239263){
        $esxititle06 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = [string]$stigsettings.accountUnlockTime.Keys
        $settingvalue = [string]$stigsettings.accountUnlockTime.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray06 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000007
Try{
    $VULID = "V-239264"
    $STIGID = "ESXI-67-000007"
    $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    $Severity = "CAT II"
    If($V239264){
        $esxititle07 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Annotations.WelcomeMessage"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Annotations.WelcomeMessage"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray07 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000008
Try{
    $VULID = "V-239265"
    $STIGID = "ESXI-67-000008"
    $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    $Severity = "CAT II"
    If($V239265){
        $esxititle08 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.banner.Keys
        $settingvalue = [string]$stigsettings.banner.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray08 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000009
Try{
    $VULID = "V-239266"
    $STIGID = "ESXI-67-000009"
    $Title = "The ESXi host SSH daemon must be configured with the Department of Defense (DoD) login banner."
    $Severity = "CAT II"
    If($V239266){
        $esxititle09 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Banner /etc/issue"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Banner /etc/issue"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray09 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000010
Try{
    $VULID = "V-239267"
    $STIGID = "ESXI-67-000010"
    $Title = "The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions."
    $Severity = "CAT II"
    If($V239267){
        $esxititle10 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray10 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-65-000011
Try{
    $VULID = "V-93969"
    $STIGID = "ESXI-65-000011"
    $Title = "The ESXi host SSH daemon must be configured to use only the SSHv2 protocol."
    $Severity = "CAT I"
    If($V93969){
        $esxititle11 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Protocol 2"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Protocol 2"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray11 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000012
Try{
    $VULID = "V-239268"
    $STIGID = "ESXI-67-000012"
    $Title = "The ESXi host SSH daemon must ignore .rhosts files."
    $Severity = "CAT II"
    If($V239268){
        $esxititle12 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "IgnoreRhosts yes"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "IgnoreRhosts yes"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray12 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000013
Try{
    $VULID = "V-239269"
    $STIGID = "ESXI-67-000013"
    $Title = "The ESXi host SSH daemon must not allow host-based authentication."
    $Severity = "CAT II"
    If($V239269){
        $esxititle13 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "HostbasedAuthentication no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "HostbasedAuthentication no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray13 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000014
Try{
    $VULID = "V-239270"
    $STIGID = "ESXI-67-000014"
    $Title = "The ESXi host SSH daemon must not allow host-based authentication."
    $Severity = "CAT III"
    If($V239270){
        $esxititle14 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results.name -eq $stigsettings.stigVibRD){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitRootLogin no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB RD Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }ElseIf($results.name -eq $stigsettings.stigVibRE){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitRootLogin no"
                    "Value" = "STIG VIB $($results.name) and root ssh logins are enabled!"
                    "Expected" = "STIG VIB RD Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
            Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitRootLogin no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB RD Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray14 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000015
Try{
    $VULID = "V-239271"
    $STIGID = "ESXI-67-000015"
    $Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
    $Severity = "CAT I"
    If($V239271){
        $esxititle15 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitEmptyPasswords no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitEmptyPasswords no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray15 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000016
Try{
    $VULID = "V-239272"
    $STIGID = "ESXI-67-000016"
    $Title = "The ESXi host SSH daemon must not permit user environment settings."
    $Severity = "CAT II"
    If($V239272){
        $esxititle16 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitUserEnvironment no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitUserEnvironment no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray16 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-65-000017
Try{
    $VULID = "V-93981"
    $STIGID = "ESXI-65-000017"
    $Title = "The ESXi host SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
    $Severity = "CAT II"
    If($V93981){
        $esxititle17 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray17 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000018
Try{
    $VULID = "V-239273"
    $STIGID = "ESXI-67-000018"
    $Title = "The ESXi host SSH daemon must not permit GSSAPI authentication."
    $Severity = "CAT III"
    If($V239273){
        $esxititle18 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "GSSAPIAuthentication no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "GSSAPIAuthentication no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray18 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000019
Try{
    $VULID = "V-239274"
    $STIGID = "ESXI-67-000019"
    $Title = "The ESXi host SSH daemon must not permit Kerberos authentication."
    $Severity = "CAT III"
    If($V239274){
        $esxititle19 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "KerberosAuthentication no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "KerberosAuthentication no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray19 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000020
Try{
    $VULID = "V-239275"
    $STIGID = "ESXI-67-000020"
    $Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
    $Severity = "CAT II"
    If($V239275){
        $esxititle20 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "StrictModes yes"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "StrictModes yes"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray20 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000021
Try{
    $VULID = "V-239276"
    $STIGID = "ESXI-67-000021"
    $Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
    $Severity = "CAT II"
    If($V239276){
        $esxititle21 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Compression no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Compression no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray21 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000022
Try{
    $VULID = "V-239277"
    $STIGID = "ESXI-67-000022"
    $Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
    $Severity = "CAT III"
    If($V239277){
        $esxititle22 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "GatewayPorts no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "GatewayPorts no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray22 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000023
Try{
    $VULID = "V-239278"
    $STIGID = "ESXI-67-000023"
    $Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
    $Severity = "CAT II"
    If($V239278){
        $esxititle23 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "X11Forwarding no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "X11Forwarding no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray23 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000024
Try{
    $VULID = "V-239279"
    $STIGID = "ESXI-67-000024"
    $Title = "The ESXi host SSH daemon must not accept environment variables from the client."
    $Severity = "CAT II"
    If($V239279){
        $esxititle24 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "AcceptEnv"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "AcceptEnv"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray24 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000025
Try{
    $VULID = "V-239280"
    $STIGID = "ESXI-67-000025"
    $Title = "The ESXi host SSH daemon must not permit tunnels."
    $Severity = "CAT II"
    If($V239280){
        $esxititle25 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitTunnel no"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "PermitTunnel no"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray25 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000026
Try{
    $VULID = "V-239281"
    $STIGID = "ESXI-67-000026"
    $Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
    $Severity = "CAT III"
    If($V239281){
        $esxititle26 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "ClientAliveCountMax 3"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "ClientAliveCountMax 3"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray26 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000027
Try{
    $VULID = "V-239282"
    $STIGID = "ESXI-67-000027"
    $Title = "The ESXi hostSSH daemon must set a timeout interval on idle sessions."
    $Severity = "CAT III"
    If($V239282){
        $esxititle27 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "ClientAliveInterval 200"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "ClientAliveInterval 200"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray27 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000028
Try{
    $VULID = "V-239283"
    $STIGID = "ESXI-67-000028"
    $Title = "The ESXi host SSH daemon must limit connections to a single session."
    $Severity = "CAT II"
    If($V239283){
        $esxititle28 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "MaxSessions 1"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "MaxSessions 1"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray28 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000029
Try{
    $VULID = "V-239284"
    $STIGID = "ESXI-67-000029"
    $Title = "The ESXi host must remove keys from the SSH authorized_keys file."
    $Severity = "CAT II"
    If($V239284){
        $esxititle29 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $results = Invoke-WebRequest -uri "https://$($vmhost.name)/host/ssh_root_authorized_keys" -Method Get -Credential $esxicred
            If($results.Content.length -gt 1){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Authorized Keys"
                    "Value" = $results.Content.substring(0,20)
                    "Expected" = "Empty File"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Authorized Keys"
                    "Value" = $results.Content
                    "Expected" = "Empty File"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray29 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsole "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000030
Try{
    $VULID = "V-239285"
    $STIGID = "ESXI-67-000030"
    $Title = "The ESXi host must produce audit records containing information to establish what type of events occurred."
    $Severity = "CAT III"
    If($V239285){
        $esxititle30 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.logLevel.Keys
        $settingvalue = [string]$stigsettings.logLevel.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray30 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000031
Try{
    $VULID = "V-239286"
    $STIGID = "ESXI-67-000031"
    $Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
    $Severity = "CAT II"
    If($V239286){
        $esxititle31 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.passComplexity.Keys
        $settingvalue = [string]$stigsettings.passComplexity.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray31 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000032
Try{
    $VULID = "V-239287"
    $STIGID = "ESXI-67-000032"
    $Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
    $Severity = "CAT II"
    If($V239287){
        $esxititle32 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.passHistory.Keys
        $settingvalue = [string]$stigsettings.passHistory.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray32 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000033
Try{
    $VULID = "V-239288"
    $STIGID = "ESXI-67-000033"
    $Title = "The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm."
    $Severity = "CAT II"
    If($V239288){
        $esxititle33 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "sha512"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "sha512"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray33 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000034
Try{
    $VULID = "V-239289"
    $STIGID = "ESXI-67-000034"
    $Title = "The ESXi host must disable the Managed Object Browser (MOB)."
    $Severity = "CAT II"
    If($V239289){
        $esxititle34 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.enableMob.Keys
        $settingvalue = [string]$stigsettings.enableMob.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray34 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000035
Try{
    $VULID = "V-239290"
    $STIGID = "ESXI-67-000035"
    $Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
    $Severity = "CAT II"
    If($V239290){
        $esxititle35 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        $servicename = "SSH"
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $vmhostservice = $vmhost | Get-VMHostService | Where {$_.Label -eq $servicename}      
            If($vmhostservice.Running -eq $true){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Service Running"
                    "Value" = $vmhostservice.Running
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Service Running"
                    "Value" = $vmhostservice.Running
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray35 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000036
Try{
    $VULID = "V-239291"
    $STIGID = "ESXI-67-000036"
    $Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
    $Severity = "CAT II"
    If($V239291){
        $esxititle36 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        $servicename = "ESXi Shell"
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $vmhostservice = $vmhost | Get-VMHostService | Where {$_.Label -eq $servicename}      
            If($vmhostservice.Running -eq $true){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Service Running"
                    "Value" = $vmhostservice.Running
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "SSH Service Running"
                    "Value" = $vmhostservice.Running
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray36 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000037
Try{
    $VULID = "V-239292"
    $STIGID = "ESXI-67-000037"
    $Title = "The ESXi host must use Active Directory for local user authentication."
    $Severity = "CAT III"
    If($V239292){
        $esxititle37 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $adstatus = $vmhost | Get-VMHostAuthentication
            If($adstatus.DomainMembershipStatus -ne "Ok" -and $adstatus.Domain -ne $stigsettings.adDomain){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Domain" = $adstatus.Domain
                    "DomainMembershipStatus" = $adstatus.DomainMembershipStatus
                    "ExpectedStatus" = "Ok"
                    "ExpectedDomain" = $stigsettings.adDomain
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Domain" = $adstatus.Domain
                    "DomainMembershipStatus" = $adstatus.DomainMembershipStatus
                    "ExpectedStatus" = "Ok"
                    "ExpectedDomain" = $stigsettings.adDomain
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray37 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsole "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000038
Try{
    $VULID = "V-239293"
    $STIGID = "ESXI-67-000038"
    $Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
    $Severity = "CAT II"
    If($V239293){
        $esxititle38 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray38 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000039
Try{
    $VULID = "V-239294"
    $STIGID = "ESXI-67-000039"
    $Title = "Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory."
    $Severity = "CAT III"
    If($V239294){
        $esxititle39 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.esxAdminsGroup.Keys
        $settingvalue = [string]$stigsettings.esxAdminsGroup.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray39 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000041
Try{
    $VULID = "V-239296"
    $STIGID = "ESXI-67-000041"
    $Title = "The ESXi host must set a timeout to automatically disable idle sessions after 10 minutes."
    $Severity = "CAT II"
    If($V239296){
        $esxititle41 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.shellIntTimeout.Keys
        $settingvalue = [string]$stigsettings.shellIntTimeout.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray41 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000042
Try{
    $VULID = "V-239297"
    $STIGID = "ESXI-67-000042"
    $Title = "The ESXi host must terminate shell services after 10 minutes."
    $Severity = "CAT II"
    If($V239297){
        $esxititle42 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.shellTimeout.Keys
        $settingvalue = [string]$stigsettings.shellTimeout.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray42 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000043
Try{
    $VULID = "V-239298"
    $STIGID = "ESXI-67-000043"
    $Title = "The ESXi host must logout of the console UI after 10 minutes."
    $Severity = "CAT II"
    If($V239298){
        $esxititle43 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.DcuiTimeOut.Keys
        $settingvalue = [string]$stigsettings.DcuiTimeOut.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray43 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000044
Try{
    $VULID = "V-239299"
    $STIGID = "ESXI-67-000044"
    $Title = "The ESXi host must enable kernel core dumps."
    $Severity = "CAT III"
    If($V239299){
        $esxititle44 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.coredump.partition.list.Invoke() | Where {$_.Active -eq "true"}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Active Core Dump Partition"
                    "Value" = $results.Name
                    "Expected" = "An Active Core Dump Partition"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Active Core Dump Partition"
                    "Value" = "No Active Core Dump Partition found!"
                    "Expected" = "An Active Core Dump Partition"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray44 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000045
Try{
    $VULID = "V-239300"
    $STIGID = "ESXI-67-000045"
    $Title = "The ESXi host must enable a persistent log location for all locally stored logs."
    $Severity = "CAT II"
    If($V239300){
        $esxititle45 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.syslogScratch.Keys
        $settingvalue = [string]$stigsettings.syslogScratch.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray45 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000046
Try{
    $VULID = "V-239301"
    $STIGID = "ESXI-67-000046"
    $Title = "The ESXi host must configure NTP time synchronization."
    $Severity = "CAT II"
    If($V239301){
        $esxititle46 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $currentntp = $vmhost.ExtensionData.Config.DateTimeInfo.ntpconfig.server
            If($currentntp.count -eq "0"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "NTP Servers"
                    "Value" = [String]::Join(',',$currentntp)
                    "Expected" = [String]::Join(',',$stigsettings.ntpServers)
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
            else{
                If($stigsettings.ntpServers[0] -ne $currentntp[0] -or $stigsettings.ntpServers[1] -ne $currentntp[1]){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = "NTP Servers"
                        "Value" = [String]::Join(',',$currentntp)
                        "Expected" = [String]::Join(',',$stigsettings.ntpServers)
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = "NTP Servers"
                        "Value" = [String]::Join(',',$currentntp)
                        "Expected" = [String]::Join(',',$stigsettings.ntpServers)
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
        }
        $esxiarray46 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000047
Try{
    $VULID = "V-239302"
    $STIGID = "ESXI-67-000047"
    $Title = "The ESXi Image Profile and VIB Acceptance Levels must be verified."
    $Severity = "CAT I"
    If($V239302){
        $esxititle47 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.acceptance.get.Invoke()
            If($results -eq "CommunitySupported"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "VIB Acceptance Level"
                    "Value" = $results
                    "Expected" = "PartnerSupported or VMwareSupported or VMwareCertified"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
            else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "VIB Acceptance Level"
                    "Value" = $results
                    "Expected" = "PartnerSupported or VMwareSupported or VMwareCertified"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray47 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000048
Try{
    $VULID = "V-239303"
    $STIGID = "ESXI-67-000048"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
    $Severity = "CAT II"
    If($V239303){
        $esxititle48 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel
            ForEach($vmk in $vmks){
                If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = "vMotion VMK Separation"
                        "Value" = "$($vmk.name) has more than 1 function enabled"
                        "Expected" = "vMotion is isolated on it's own VMkernel"
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }ElseIf($vmk.VMotionEnabled -eq "True"){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = "vMotion VMK Separation"
                        "Value" = "$($vmk.name) has only vMotion enabled"
                        "Expected" = "vMotion is isolated on it's own VMkernel"
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }      
        }
        $esxiarray48 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000049
Try{
    $VULID = "V-239304"
    $STIGID = "ESXI-67-000049"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
    $Severity = "CAT II"
    If($V239304){
        $esxititle49 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray49 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000050
Try{
    $VULID = "V-239305"
    $STIGID = "ESXI-67-000050"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
    $Severity = "CAT II"
    If($V239305){
        $esxititle50 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray50 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000052
Try{
    $VULID = "V-239306"
    $STIGID = "ESXI-67-000052"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by utilizing different TCP/IP stacks where possible."
    $Severity = "CAT III"
    If($V239306){
        $esxititle52 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray52 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000053
Try{
    $VULID = "V-239307"
    $STIGID = "ESXI-67-000053"
    $Title = "SNMP must be configured properly on the ESXi host."
    $Severity = "CAT II"
    If($V239307){
        $esxititle53 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.system.snmp.get.Invoke() | Where {$_.enable -eq "true"}
            If($results.communities){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Enabled" = $results.enable
                    "communities" = $results.communities
                    "v3targets" = $results.v3targets
                    "Expected" = "SNMP v1/2 is not in use"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }ElseIf($results.v3targets){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Enabled" = $results.enable
                    "communities" = $results.communities
                    "v3targets" = $results.v3targets
                    "Expected" = "SNMP v1/2 is not in use"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Enabled" = $false
                    "communities" = $results.communities
                    "v3targets" = $results.v3targets
                    "Expected" = "SNMP v1/2 is not in use"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray53 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000054
Try{
    $VULID = "V-239308"
    $STIGID = "ESXI-67-000054"
    $Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
    $Severity = "CAT III"
    If($V239308){
        $esxititle54 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray54 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000055
Try{
    $VULID = "V-239309"
    $STIGID = "ESXI-67-000055"
    $Title = "The ESXi host must disable Inter-VM transparent page sharing."
    $Severity = "CAT III"
    If($V239309){
        $esxititle55 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.ShareForceSalting.Keys
        $settingvalue = [string]$stigsettings.ShareForceSalting.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray55 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000056
Try{
    $VULID = "V-239310"
    $STIGID = "ESXI-67-000056"
    $Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
    $Severity = "CAT II"
    If($V239310){
        $esxititle56 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $fwservices = $vmhost | Get-VMHostFirewallException | Where {$_.Enabled -eq $True}
            ForEach($fwservice in $fwservices){
                If($fwservice.extensiondata.allowedhosts.IpNetwork){
                    #Extract allowed networks from configuration for comparison
                    $allowedNetworks = @()
                    $netcount = $fwservice.extensiondata.allowedhosts.IpNetwork.count
                    For($i=0; $i -lt $netcount; $i++){
                        $newnet = $fwservice.extensiondata.allowedhosts.IpNetwork[$i].Network + "/" + $fwservice.extensiondata.allowedhosts.IpNetwork[$i].PrefixLength
                        $allowedNetworks += $newnet
                    }
                    $allowedNetworksStr = [String]::Join(',',$allowedNetworks)
                    $expectedNetworksStr = [String]::Join(',',$stigSettings.allowedNetworks)
                }Else{
                    $allowedNetworks = $fwservice.extensiondata.allowedhosts.IpNetwork
                    $allowedNetworksStr = ""
                    If($stigSettings.allowedNetworks){
                        $expectedNetworksStr = [String]::Join(',',$stigSettings.allowedNetworks)
                    }Else{
                        $expectedNetworksStr = ""
                    }
                }
                If($fwservice.extensiondata.allowedhosts.IpAddress){
                    $allowedIPs = $fwservice.extensiondata.allowedhosts.IpAddress
                    $allowedIPsStr = [String]::Join(',',$fwservice.extensiondata.allowedhosts.IpAddress)
                    #$expectedIPsStr = [String]::Join(',',$stigSettings.allowedIps)
                    $expectedIPsStr = $stigSettings.allowedIps | Out-String
                }Else{
                    $allowedIPs = $fwservice.extensiondata.allowedhosts.IpAddress
                    $allowedIPsStr = ""
                    If($stigSettings.allowedIps){
                        $expectedIPsStr = [String]::Join(',',$stigSettings.allowedIps)
                    }Else{
                        $expectedIPsStr = ""
                    }
                }
                If($fwservice.extensiondata.allowedhosts.allip -eq $true -or $allowedNetworksStr -ne $expectedNetworksStr -or $allowedIPsStr -ne $expectedIPsStr){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Service" = $fwservice.name
                        "AllIPsEnabled" = $fwservice.extensiondata.allowedhosts.allip
                        "AllowedIPNetworks" = $allowedNetworksStr
                        "AllowedIPs" = $allowedIPsStr
                        "Expected" = "All IPs allowed Disabled"
                        "Expected Allowed IP Ranges" = $expectedNetworksStr
                        "Expected Allowed IPs" = $expectedIPsStr
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Service" = $fwservice.name
                        "AllIPsEnabled" = $fwservice.extensiondata.allowedhosts.allip
                        "AllowedIPNetworks" = $allowedNetworksStr
                        "AllowedIPs" = $allowedIPsStr
                        "Expected" = "All IPs allowed Disabled"
                        "Expected Allowed IP Ranges" = $expectedNetworksStr
                        "Expected Allowed IPs" = $expectedIPsStr
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
        }
        $esxiarray56 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000057
Try{
    $VULID = "V-239311"
    $STIGID = "ESXI-67-000057"
    $Title = "The ESXi host must configure the firewall to block network traffic by default."
    $Severity = "CAT II"
    If($V239311){
        $esxititle57 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $results = $vmhost | Get-VMHostFirewallDefaultPolicy
            If($results.IncomingEnabled -eq "True" -xor $results.OutgoingEnabled -eq "True"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Default Firewall Policy"
                    "IncomingEnabled" = $results.IncomingEnabled
                    "OutgoingEnabled" = $results.OutgoingEnabled
                    "Expected" = "Incoming/Outgoing traffic blocked by default"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Default Firewall Policy"
                    "IncomingEnabled" = $results.IncomingEnabled
                    "OutgoingEnabled" = $results.OutgoingEnabled
                    "Expected" = "Incoming/Outgoing traffic blocked by default"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray57 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000058
Try{
    $VULID = "V-239312"
    $STIGID = "ESXI-67-000058"
    $Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
    $Severity = "CAT III"
    If($V239312){
        $esxititle58 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.BlockGuestBPDU.Keys
        $settingvalue = [string]$stigsettings.BlockGuestBPDU.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray58 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000059
Try{
    $VULID = "V-239313"
    $STIGID = "ESXI-67-000059"
    $Title = "The virtual switch Forged Transmits policy must be set to reject on the ESXi host."
    $Severity = "CAT II"
    If($V239313){
        $esxititle59 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Switch" = "N/A"
                    "Port Group" = "N/A"
                    "ForgedTransmits" = "N/A"
                    "ForgedTransmitsInherited" = "N/A"
                    "Expected" = "No vSwitches or Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.ForgedTransmits -eq $true){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "ForgedTransmits" = $secpol.ForgedTransmits
                            "ForgedTransmitsInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "ForgedTransmits" = $secpol.ForgedTransmits
                            "ForgedTransmitsInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.ForgedTransmits -eq $true -or $secpol.ForgedTransmitsInherited -eq $false){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "ForgedTransmits" = $secpol.ForgedTransmits
                            "ForgedTransmitsInherited" = $secpol.ForgedTransmitsInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "ForgedTransmits" = $secpol.ForgedTransmits
                            "ForgedTransmitsInherited" = $secpol.ForgedTransmitsInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray59 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000060
Try{
    $VULID = "V-239314"
    $STIGID = "ESXI-67-000060"
    $Title = "The virtual switch MAC Address Change policy must be set to reject on the ESXi host."
    $Severity = "CAT I"
    If($V239314){
        $esxititle60 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Switch" = "N/A"
                    "Port Group" = "N/A"
                    "MacChanges" = "N/A"
                    "MacChangesInherited" = "N/A"
                    "Expected" = "No vSwitches or Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.MacChanges -eq $true){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "MacChanges" = $secpol.MacChanges
                            "MacChangesInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "MacChanges" = $secpol.MacChanges
                            "MacChangesInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.MacChanges -eq $true -or $secpol.MacChangesInherited -eq $false){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "MacChanges" = $secpol.MacChanges
                            "MacChangesInherited" = $secpol.MacChangesInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "MacChanges" = $secpol.MacChanges
                            "MacChangesInherited" = $secpol.MacChangesInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray60 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000061
Try{
    $VULID = "V-239315"
    $STIGID = "ESXI-67-000061"
    $Title = "The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host."
    $Severity = "CAT II"
    If($V239315){
        $esxititle61 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Switch" = "N/A"
                    "Port Group" = "N/A"
                    "AllowPromiscuous" = "N/A"
                    "AllowPromiscuousInherited" = "N/A"
                    "Expected" = "No vSwitches or Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                ForEach($sw in $switches){
                    $secpol = $sw | Get-SecurityPolicy
                    If($secpol.AllowPromiscuous -eq $true){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "AllowPromiscuous" = $secpol.AllowPromiscuous
                            "AllowPromiscuousInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = $sw.name
                            "Port Group" = "N/A"
                            "AllowPromiscuous" = $secpol.AllowPromiscuous
                            "AllowPromiscuousInherited" = "N/A"
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    $secpol = $pg | Get-SecurityPolicy
                    If($secpol.AllowPromiscuous -eq $true -or $secpol.AllowPromiscuousInherited -eq $false){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "AllowPromiscuous" = $secpol.AllowPromiscuous
                            "AllowPromiscuousInherited" = $secpol.AllowPromiscuousInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Switch" = "N/A"
                            "Port Group" = $pg.name
                            "AllowPromiscuous" = $secpol.AllowPromiscuous
                            "AllowPromiscuousInherited" = $secpol.AllowPromiscuousInherited
                            "Expected" = "No vSwitches or Forged Transmits Disabled"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray61 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000062
Try{
    $VULID = "V-239316"
    $STIGID = "ESXI-67-000062"
    $Title = "The ESXi host must prevent unintended use of the dvFilter network APIs."
    $Severity = "CAT II"
    If($V239316){
        $esxititle62 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.DVFilterBindIpAddress.Keys
        $settingvalue = [string]$stigsettings.DVFilterBindIpAddress.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray62 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000063
Try{
    $VULID = "V-239317"
    $STIGID = "ESXI-67-000063"
    $Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
    $Severity = "CAT II"
    If($V239317){
        $esxititle63 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Port Group" = "N/A"
                    "VLAN ID" = "N/A"
                    "Expected" = "No vSwitches or native vlan id: $($stigsettings.nativeVLANid)"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    If($pg.VlanId -eq $stigsettings.nativeVLANid){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or native vlan id: $($stigsettings.nativeVLANid)"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or native vlan id: $($stigsettings.nativeVLANid)"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray63 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000064
Try{
    $VULID = "V-239318"
    $STIGID = "ESXI-67-000064"
    $Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
    $Severity = "CAT II"
    If($V239318){
        $esxititle64 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Port Group" = "N/A"
                    "VLAN ID" = "N/A"
                    "Expected" = "No vSwitches or trunk vlan id: 4095"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    If($pg.VlanId -eq "4095"){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or trunk vlan id: 4095"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or trunk vlan id: 4095"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray64 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000065
Try{
    $VULID = "V-239319"
    $STIGID = "ESXI-67-000065"
    $Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
    $Severity = "CAT II"
    If($V239319){
        $esxititle65 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $switches = Get-VirtualSwitch -VMHost $vmhost -Standard
            If($switches.count -eq 0){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Port Group" = "N/A"
                    "VLAN ID" = "N/A"
                    "Expected" = "No vSwitches or reserved vlan ids"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
                ForEach($pg in $portgroups){
                    If($pg.VlanId -In 1001..1024 -or $pg.VlanId -In 3968..4047 -or $pg.VlanId -In 4094){
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or reserved vlan ids"
                            "Severity" = $Severity
                            "Compliant" = $false
                        })
                    }Else{
                        $esxiarray += New-Object PSObject -Property ([ordered]@{
                            "Name" = $vmhost.name
                            "Port Group" = $pg.name
                            "VLAN ID" = $pg.vlanid
                            "Expected" = "No vSwitches or reserved vlan ids"
                            "Severity" = $Severity
                            "Compliant" = $true
                        })
                    }
                }
            }
        }
        $esxiarray65 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000072
Try{
    $VULID = "V-239325"
    $STIGID = "ESXI-67-000072"
    $Title = "The ESXi host must have all security patches and updates installed."
    $Severity = "CAT I"
    If($V239325){
        $esxititle72 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $build = $vmhost.ExtensionData.Config.Product.build
            If($build -ne $stigsettings.esxiLatestBuild){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Current Build" = $build
                    "Expected Build" = $stigsettings.esxiLatestBuild
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Current Build" = $build
                    "Expected Build" = $stigsettings.esxiLatestBuild
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $esxiarray72 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## ESXI-67-000074
Try{
    $VULID = "V-239326"
    $STIGID = "ESXI-67-000074"
    $Title = "The ESXi host must exclusively enable TLS 1.2 for all endpoints."
    $Severity = "CAT II"
    If($V239326){
        $esxititle74 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        $settingname = $stigsettings.sslProtocols.Keys
        $settingvalue = [string]$stigsettings.sslProtocols.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray74 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000076
Try{
    $VULID = "V-239327"
    $STIGID = "ESXI-67-000076"
    $Title = "The ESXi host must enable Secure Boot."
    $Severity = "CAT II"
    If($V239327){
        $esxititle76 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
        }
        $esxiarray76 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000078
Try{
    $VULID = "V-239328"
    $STIGID = "ESXI-67-000078"
    $Title = "The ESXi host must use DoD-approved certificates."
    $Severity = "CAT II"
    If($V239328){
        $esxititle78 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"
            $result = Test-WebServerSSL -URL $vmhost.name
            If($result.Certificate.Issuer -match $stigsettings.certAuthName){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Cert Issuer" = $result.Certificate.Issuer
                    "Cert Expires" = $result.Certificate.NotAfter
                    "Cert Serial" = $result.Certificate.SerialNumber
                    "Cert Thumbprint" = $result.Certificate.Thumbprint
                    "Expected" = "Certificate issued from a DoD CA and valid"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Cert Issuer" = $result.Certificate.Issuer
                    "Cert Expires" = $result.Certificate.NotAfter
                    "Cert Serial" = $result.Certificate.SerialNumber
                    "Cert Thumbprint" = $result.Certificate.Thumbprint
                    "Expected" = "Certificate issued from a DoD CA and valid"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }

        }
        $esxiarray78 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsole "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-000079
Try{
    $VULID = "V-239329"
    $STIGID = "ESXI-67-000079"
    $Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
    $Severity = "CAT II"
    If($V239329){
        $esxititle79 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        $settingname = [string]$stigsettings.SuppressShellWarning.Keys
        $settingvalue = [string]$stigsettings.SuppressShellWarning.Values
        Write-ToConsoleRed "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray79 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsole "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-100004
Try{
    $VULID = "V-239330"
    $STIGID = "ESXI-67-100004"
    $Title = "The ESXi host must centrally review and analyze audit records from multiple components within the system by configuring remote logging."
    $Severity = "CAT II"
    If($V239330){
        $esxititle100004 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        $settingname = [string]$stigsettings.syslogHost.Keys
        $settingvalue = [string]$stigsettings.syslogHost.Values
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhostsv){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $settingname"        
            If($vmhost.Config.option.key -contains "$settingname"){
                $currentvalue = $vmhost.Config.option | where {$_.key -eq "$settingname"}
                If($currentvalue.value -ne $settingvalue){
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $false
                    })
                }
                Else{
                    $esxiarray += New-Object PSObject -Property ([ordered]@{
                        "Name" = $vmhost.name
                        "Setting" = $currentvalue.key
                        "Value" = $currentvalue.value
                        "Expected" = $settingvalue
                        "Severity" = $Severity
                        "Compliant" = $true
                    })
                }
            }
            If($vmhost.Config.option.key -notcontains "$settingname"){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = $settingname
                    "Value" = "Setting does not exist on ESXi Host"
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray100004 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsole "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

# ESXI-67-100010
Try{
    $VULID = "V-239331"
    $STIGID = "ESXI-67-100010"
    $Title = "The ESXi host SSH daemon must be configured to only use FIPS 140-2 approved ciphers."
    $Severity = "CAT II"
    If($V239331){
        $esxititle100010 = "Vulnerability ID:$VULID STIG ID:$STIGID Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
        $esxiarray = @()
        ForEach($vmhost in $vmhosts){
            Write-ToConsole "...Checking ESXi Host $($vmhost.Name) for $title"        
            $esxcli = Get-EsxCli -VMHost $vmhost -V2
            $results = $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq $stigsettings.stigVibRE -or $_.Name -eq $stigsettings.stigVibRD}
            If($results){
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
                    "Value" = "Set by STIG VIB $($results.name)"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $esxiarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vmhost.name
                    "Setting" = "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
                    "Value" = "STIG VIB NOT installed"
                    "Expected" = "STIG VIB Installed"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $esxiarray100010 = Set-TableRowColor -ArrayOfObjects $esxiarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vmhostsarrayall += $esxiarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID with Title: $Title on $($vmhost.name)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

#End ESXi Processing

#Begin vCenter Processing
#Initialize array for vc data
$vcarrayall = @()

## VCWN-65-000005
Try{
    $VULID = "V-94725"
    $STIGID = "VCWN-65-000005"
    $Title = "The vCenter Server users must have the correct roles assigned."
    $Severity = "CAT II"
    If($V94725){
        $vctitle05 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        $perms = Get-VIPermission | Sort-Object -Property Role | Select Role,Principal,Entity,Propagate,IsGroup
        ForEach($perm in $perms){
            $vcarray += New-Object PSObject -Property ([ordered]@{
                "Name" = $vcenter
                "Role" = $perm.role
                "Principal" = $perm.Principal
                "Entity" = $perm.Entity
                "Propagate" = $perm.Propagate
                "IsGroup" = $perm.IsGroup
                "Expected" = "Verify Permissions are accurate"
                "Severity" = $Severity
                "Compliant" = $true
            })
        }
        $vcarray05 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000007
Try{
    $VULID = "V-94727"
    $STIGID = "VCWN-65-000007"
    $Title = "The vCenter Server for Windows must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks by enabling Network I/O Control (NIOC)."
    $Severity = "CAT II"
    If($V94727){
        $vctitle07 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"        
            If($vds.ExtensionData.config.NetworkResourceManagementEnabled -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Setting" = "Network I/O Control"
                    "Value" = $vds.ExtensionData.config.NetworkResourceManagementEnabled
                    "Expected" = $true
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Setting" = "Network I/O Control"
                    "Value" = $vds.ExtensionData.config.NetworkResourceManagementEnabled
                    "Expected" = $true
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }
        }
        $vcarray07 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000012
Try{
    $VULID = "V-94735"
    $STIGID = "VCWN-65-000012"
    $Title = "The vCenter Server for Windows must disable the distributed virtual switch health check."
    $Severity = "CAT III"
    If($V94735){
        $vctitle12 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"        
            If($vds.ExtensionData.config.HealthCheckConfig.Enable[0] -eq $true -or $vds.ExtensionData.config.HealthCheckConfig.Enable[1] -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.Name
                    "VLAN/MTU Health Check" = $vds.ExtensionData.config.HealthCheckConfig.Enable[0]
                    "Teaming/Failover Health Check" = $vds.ExtensionData.config.HealthCheckConfig.Enable[1]
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.Name
                    "VLAN/MTU Health Check" = $vds.ExtensionData.config.HealthCheckConfig.Enable[0]
                    "Teaming/Failover Health Check" = $vds.ExtensionData.config.HealthCheckConfig.Enable[1]
                    "Expected" = $false
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray12 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000013
Try{
    $VULID = "V-94737"
    $STIGID = "VCWN-65-000013"
    $Title = "The vCenter Server for Windows must set the distributed port group Forged Transmits policy to reject."
    $Severity = "CAT II"
    If($V94737){
        $vctitle13 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"        
            $secpol = $vds | Get-VDSecurityPolicy
            If($secpol.ForgedTransmits -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "ForgedTransmits" = $secpol.ForgedTransmits
                    "Expected" = "Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "ForgedTransmits" = $secpol.ForgedTransmits
                    "Expected" = "Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        ForEach($pg in $dportgroups){
            $secpol = $pg | Get-VDSecurityPolicy
            If($secpol.ForgedTransmits -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "ForgedTransmits" = $secpol.ForgedTransmits
                    "Expected" = "Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "ForgedTransmits" = $secpol.ForgedTransmits
                    "Expected" = "Forged Transmits Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray13 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000014
Try{
    $VULID = "V-94739"
    $STIGID = "VCWN-65-000014"
    $Title = "The vCenter Server must set the distributed port group MAC Address Change policy to reject."
    $Severity = "CAT I"
    If($V94739){
        $vctitle14 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"        
            $secpol = $vds | Get-VDSecurityPolicy
            If($secpol.MacChanges -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "MacChanges" = $secpol.MacChanges
                    "Expected" = "MAC Address Changes Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "MacChanges" = $secpol.MacChanges
                    "Expected" = "MAC Address Changes Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        ForEach($pg in $dportgroups){
            $secpol = $pg | Get-VDSecurityPolicy
            If($secpol.MacChanges -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "MacChanges" = $secpol.MacChanges
                    "Expected" = "MAC Address Changes Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "MacChanges" = $secpol.MacChanges
                    "Expected" = "MAC Address Changes Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray14 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000015
Try{
    $VULID = "V-94741"
    $STIGID = "VCWN-65-000015"
    $Title = "The vCenter Server must set the distributed port group Promiscuous Mode policy to reject."
    $Severity = "CAT II"
    If($V94741){
        $vctitle15 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"        
            $secpol = $vds | Get-VDSecurityPolicy
            If($secpol.AllowPromiscuous -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "AllowPromiscuous" = $secpol.AllowPromiscuous
                    "Expected" = "Allow Promiscious Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "AllowPromiscuous" = $secpol.AllowPromiscuous
                    "Expected" = "Allow Promiscious Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        ForEach($pg in $dportgroups){
            $secpol = $pg | Get-VDSecurityPolicy
            If($secpol.AllowPromiscuous -eq $true){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "AllowPromiscuous" = $secpol.AllowPromiscuous
                    "Expected" = "Allow Promiscious Disabled"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "AllowPromiscuous" = $secpol.AllowPromiscuous
                    "Expected" = "Allow Promiscious Disabled"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray15 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000016
Try{
    $VULID = "V-94743"
    $STIGID = "VCWN-65-000016"
    $Title = "The vCenter Server must only send NetFlow traffic to authorized collectors."
    $Severity = "CAT II"
    If($V94743){
        $vctitle16 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($vds in $vdswitches){
            Write-ToConsole "...Checking Distributed Switch $vcenter for $title"
            If($vds.ExtensionData.config.IpfixConfig.CollectorIpAddress){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "Netflow Collector" = $vds.ExtensionData.config.IpfixConfig.CollectorIpAddress
                    "Expected" = "Blank if not in use"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = $vds.name
                    "Port Group" = "N/A"
                    "Netflow Collector" = $vds.ExtensionData.config.IpfixConfig.CollectorIpAddress
                    "Expected" = "Blank if not in use temporarily"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        ForEach($pg in $dportgroups){
            If($pg.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "IPFIX Enabled" = $pg.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value
                    "Expected" = "False if not in use temporarily"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Switch" = "N/A"
                    "Port Group" = $pg.name
                    "IPFIX Enabled" = $pg.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value
                    "Expected" = "False if not in use temporarily"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray16 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000017
Try{
    $VULID = "V-94745"
    $STIGID = "VCWN-65-000016"
    $Title = "The vCenter Server must not override port group settings at the port level on distributed switches."
    $Severity = "CAT III"
    If($V94745){
        $vctitle17 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($pg in $dportgroups){
            If($pg.ExtensionData.Config.Policy.VlanOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.IpfixOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.MacManagementOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.BlockOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.ShapingOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.LivePortMovingAllowed -eq $true -or $pg.ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed -eq $true -or $pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed -eq $true){                
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Override" = $pg.ExtensionData.Config.Policy.VlanOverrideAllowed
                    "UplinkTeamingOverride" = $pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed
                    "SecurityPolicyOverride" = $pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed
                    "IpFixOverride" = $pg.ExtensionData.Config.Policy.IpfixOverrideAllowed
                    "MacOverride" = $pg.ExtensionData.Config.Policy.MacManagementOverrideAllowed
                    "BlockOverride" = $pg.ExtensionData.Config.Policy.BlockOverrideAllowed
                    "ShapingOverride" = $pg.ExtensionData.Config.Policy.ShapingOverrideAllowed
                    "VendorOverride" = $pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed
                    "LivePortOverride" = $pg.ExtensionData.Config.Policy.LivePortMovingAllowed
                    "NetworkResourceOverride" = $pg.ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed
                    "TrafficFilterOverride" = $pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed
                    "Expected" = "False"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Override" = $pg.ExtensionData.Config.Policy.VlanOverrideAllowed
                    "UplinkTeamingOverride" = $pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed
                    "SecurityPolicyOverride" = $pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed
                    "IpFixOverride" = $pg.ExtensionData.Config.Policy.IpfixOverrideAllowed
                    "MacOverride" = $pg.ExtensionData.Config.Policy.MacManagementOverrideAllowed
                    "BlockOverride" = $pg.ExtensionData.Config.Policy.BlockOverrideAllowed
                    "ShapingOverride" = $pg.ExtensionData.Config.Policy.ShapingOverrideAllowed
                    "VendorOverride" = $pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed
                    "LivePortOverride" = $pg.ExtensionData.Config.Policy.LivePortMovingAllowed
                    "NetworkResourceOverride" = $pg.ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed
                    "TrafficFilterOverride" = $pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed
                    "Expected" = "False"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray17 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000018
Try{
    $VULID = "V-94747"
    $STIGID = "VCWN-65-000018"
    $Title = "The vCenter Server must configure all port groups to a value other than that of the native VLAN."
    $Severity = "CAT II"
    If($V94747){
        $vctitle18 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($pg in $dportgroups){
            If($pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId -eq $stigsettings.nativeVLANid){                
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Id" = $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId
                    "Expected" = "Not configured to Native VLAN ID: $($stigsettings.nativeVLANid)"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Id" = $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId
                    "Expected" = "Not configured to Native VLAN ID: $($stigsettings.nativeVLANid)"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray18 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000019
Try{
    $VULID = "V-94749"
    $STIGID = "VCWN-65-000019"
    $Title = "The vCenter Server must not configure all port groups to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
    $Severity = "CAT II"
    If($V94749){
        $vctitle19 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($pg in $dportgroups){
            If($pg.VlanConfiguration.VlanType -eq "Trunk"){                
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Type" = $pg.VlanConfiguration.VlanType
                    "Expected" = "Not trunk"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Type" = $pg.VlanConfiguration.VlanType
                    "Expected" = "Not trunk"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray19 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000020
Try{
    $VULID = "V-94751"
    $STIGID = "VCWN-65-000020"
    $Title = "The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches."
    $Severity = "CAT II"
    If($V94751){
        $vctitle20 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        ForEach($pg in $dportgroups){
            If($pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId -In 1001..1024 -or $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId -In 3968..4047 -or $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId -In 4094){                
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Id" = $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId
                    "Expected" = "Not configured to Reserved VLAN ID"
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Port Group" = $pg.name
                    "VLAN Id" = $pg.ExtensionData.Config.defaultPortConfig.Vlan.VlanId
                    "Expected" = "Not configured to Reserved VLAN ID"
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }
        $vcarray20 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

## VCWN-65-000036
Try{
    $VULID = "V-94781"
    $STIGID = "VCWN-65-000036"
    $Title = "The vCenter Server must produce audit records containing information to establish what type of events occurred."
    $Severity = "CAT III"
    If($V94781){
        $vctitle36 = "Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity Title: $Title"
        Write-ToConsole "...Checking STIG Control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
        $vcarray = @()
        $settingname = [string]$stigsettings.vcLogLevel.keys
        $settingvalue = [string]$stigsettings.vcLogLevel.values
        $currentsetting = Get-AdvancedSetting -Entity $vcenter -Name $settingname
        If($currentsetting){
            If($currentsetting.value -ne $settingvalue){
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Setting" = $settingname
                    "Value" = $currentsetting.value
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $false
                })
            }Else{
                $vcarray += New-Object PSObject -Property ([ordered]@{
                    "Name" = $vcenter
                    "Setting" = $settingname
                    "Value" = $currentsetting.value
                    "Expected" = $settingvalue
                    "Severity" = $Severity
                    "Compliant" = $true
                })
            }
        }Else{
            $vcarray += New-Object PSObject -Property ([ordered]@{
                "Name" = $vcenter
                "Setting" = $settingname
                "Value" = "Setting does not exist!"
                "Expected" = $settingvalue
                "Severity" = $Severity
                "Compliant" = $false
            })
        }
        $vcarray36 = Set-TableRowColor -ArrayOfObjects $vcarray -Red '$this.Compliant -eq $false' | Sort-Object -Property @{Expression = {$_.RowColor}; Ascending = $false},Name
        $vcarrayall += $vcarray
    }
    Else{
        Write-ToConsoleRed "...Skipping disabled control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title"
    }
}
Catch{
    Write-Error "Failed to check control with Vulnerability ID:$VULID STIG ID:$STIGID Severity:$Severity with Title: $Title on $($vcenter)"
    Write-Error $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $vcenter"
    Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    Exit -1
}

#End vCenter Processing


##Build Overview Data
Write-ToConsole "...Building HTML Report..."

##Virtual Machine Compliance Overall
$vmsarrayallcompliantcount = @($vmsarrayall | Where {$_.Compliant -eq $true}).count
$vmsarrayallnoncompliantcount = @($vmsarrayall | Where {$_.Compliant -eq $false}).count

##Virtual Machine Compliance By Severity
$vmscompliantcountcat1 = @($vmsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT I"}).count
$vmsnoncompliantcountcat1 = @($vmsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT I"}).count
$vmscompliantcountcat2 = @($vmsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT II"}).count
$vmsnoncompliantcountcat2 = @($vmsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT II"}).count
$vmscompliantcountcat3 = @($vmsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT III"}).count
$vmsnoncompliantcountcat3 = @($vmsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT III"}).count

#Generate VM Compliance table
$vmcomptable = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant" + ": $vmsarrayallnoncompliantcount"
    'Count' = $vmsarrayallnoncompliantcount
    }
$vmcomptable.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant" + ": $vmsarrayallcompliantcount"
    'Count' = $vmsarrayallcompliantcount
    }
$vmcomptable.Add($obj1)

#Generate VM Compliance table by Severity
$vmcomptablesev = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT I" + ": $vmsnoncompliantcountcat1"
    'Count' = $vmsnoncompliantcountcat1
    }
$vmcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT I" + ": $vmscompliantcountcat1"
    'Count' = $vmscompliantcountcat1
    }
$vmcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT II" + ": $vmsnoncompliantcountcat2"
    'Count' = $vmsnoncompliantcountcat2
    }
$vmcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT II" + ": $vmscompliantcountcat2"
    'Count' = $vmscompliantcountcat2
    }
$vmcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT III" + ": $vmsnoncompliantcountcat3"
    'Count' = $vmsnoncompliantcountcat3
    }
$vmcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT III" + ": $vmscompliantcountcat3"
    'Count' = $vmscompliantcountcat3
    }
$vmcomptablesev.Add($obj1)

##VM Compliance Pie Chart
$PieObjectVMCompliance = Get-HTMLPieChartObject
$PieObjectVMCompliance.Title = "VM Overall Compliance"
$PieObjectVMCompliance.Size.Height = 250
$PieObjectVMCompliance.Size.Width = 250
$PieObjectVMCompliance.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVMCompliance.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVMCompliance.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVMCompliance.DataDefinition.DataValueColumnName = 'Count'

##VM Severity Compliance Pie Chart
$PieObjectVMComplianceSev = Get-HTMLPieChartObject
$PieObjectVMComplianceSev.Title = "VM Overall Compliance by Severity"
$PieObjectVMComplianceSev.Size.Height = 250
$PieObjectVMComplianceSev.Size.Width = 250
$PieObjectVMComplianceSev.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVMComplianceSev.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVMComplianceSev.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVMComplianceSev.DataDefinition.DataValueColumnName = 'Count'


##ESXi Compliance Overall
$vmhostsarrayallcompliantcount = @($vmhostsarrayall | Where {$_.Compliant -eq $true}).count
$vmhostsarrayallnoncompliantcount = @($vmhostsarrayall | Where {$_.Compliant -eq $false}).count

##ESXi Compliance By Severity
$vmhostscompliantcountcat1 = @($vmhostsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT I"}).count
$vmhostsnoncompliantcountcat1 = @($vmhostsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT I"}).count
$vmhostscompliantcountcat2 = @($vmhostsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT II"}).count
$vmhostsnoncompliantcountcat2 = @($vmhostsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT II"}).count
$vmhostscompliantcountcat3 = @($vmhostsarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT III"}).count
$vmhostsnoncompliantcountcat3 = @($vmhostsarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT III"}).count

#Generate ESXi Compliance table
$vmhostcomptable = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant" + ": $vmhostsarrayallnoncompliantcount"
    'Count' = $vmhostsarrayallnoncompliantcount
    }
$vmhostcomptable.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant" + ": $vmhostsarrayallcompliantcount"
    'Count' = $vmhostsarrayallcompliantcount
    }
$vmhostcomptable.Add($obj1)

#Generate ESXi Severity Compliance table
$vmhostcomptablesev = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT I" + ": $vmhostsnoncompliantcountcat1"
    'Count' = $vmhostsnoncompliantcountcat1
    }
$vmhostcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT I" + ": $vmhostscompliantcountcat1"
    'Count' = $vmhostscompliantcountcat1
    }
$vmhostcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT II" + ": $vmhostsnoncompliantcountcat2"
    'Count' = $vmhostsnoncompliantcountcat2
    }
$vmhostcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT II" + ": $vmhostscompliantcountcat2"
    'Count' = $vmhostscompliantcountcat2
    }
$vmhostcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT III" + ": $vmhostsnoncompliantcountcat3"
    'Count' = $vmhostsnoncompliantcountcat3
    }
$vmhostcomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT III" + ": $vmhostscompliantcountcat3"
    'Count' = $vmhostscompliantcountcat3
    }
$vmhostcomptablesev.Add($obj1)

##ESXi Compliance Pie Chart
$PieObjectVMHostCompliance = Get-HTMLPieChartObject
$PieObjectVMHostCompliance.Title = "ESXi Overall Compliance"
$PieObjectVMHostCompliance.Size.Height = 250
$PieObjectVMHostCompliance.Size.Width = 250
$PieObjectVMHostCompliance.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVMHostCompliance.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVMHostCompliance.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVMHostCompliance.DataDefinition.DataValueColumnName = 'Count'

##ESXi Severity Compliance Pie Chart
$PieObjectVMHostComplianceSev = Get-HTMLPieChartObject
$PieObjectVMHostComplianceSev.Title = "ESXi Overall Compliance by Severity"
$PieObjectVMHostComplianceSev.Size.Height = 250
$PieObjectVMHostComplianceSev.Size.Width = 250
$PieObjectVMHostComplianceSev.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVMHostComplianceSev.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVMHostComplianceSev.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVMHostComplianceSev.DataDefinition.DataValueColumnName = 'Count'

##vCenter Compliance Overall
$vcarrayallcompliantcount = @($vcarrayall | Where {$_.Compliant -eq $true}).count
$vcarrayallnoncompliantcount = @($vcarrayall | Where {$_.Compliant -eq $false}).count

##Virtual Machine Compliance By Severity
$vccompliantcountcat1 = @($vcarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT I"}).count
$vcnoncompliantcountcat1 = @($vcarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT I"}).count
$vccompliantcountcat2 = @($vcarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT II"}).count
$vcnoncompliantcountcat2 = @($vcarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT II"}).count
$vccompliantcountcat3 = @($vcarrayall | Where {$_.Compliant -eq $true -and $_.Severity -eq "CAT III"}).count
$vcnoncompliantcountcat3 = @($vcarrayall | Where {$_.Compliant -eq $false -and $_.Severity -eq "CAT III"}).count

#Generate vCenter Compliance table
$vccomptable = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant" + ": $vcarrayallnoncompliantcount"
    'Count' = $vcarrayallnoncompliantcount
    }
$vccomptable.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant" + ": $vcarrayallcompliantcount"
    'Count' = $vcarrayallcompliantcount
    }
$vccomptable.Add($obj1)

#Generate vCenter Severity Compliance table
$vccomptablesev = New-Object 'System.Collections.Generic.List[System.Object]'

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT I" + ": $vcnoncompliantcountcat1"
    'Count' = $vcnoncompliantcountcat1
    }
$vccomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT I" + ": $vccompliantcountcat1"
    'Count' = $vccompliantcountcat1
    }
$vccomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT II" + ": $vcnoncompliantcountcat2"
    'Count' = $vcnoncompliantcountcat2
    }
$vccomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT II" + ": $vccompliantcountcat2"
    'Count' = $vccompliantcountcat2
    }
$vccomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Non-Compliant CAT III" + ": $vcnoncompliantcountcat3"
    'Count' = $vcnoncompliantcountcat3
    }
$vccomptablesev.Add($obj1)

$obj1 = [PSCustomObject]@{
    'Name'  = "Compliant CAT III" + ": $vccompliantcountcat3"
    'Count' = $vccompliantcountcat3
    }
$vccomptablesev.Add($obj1)

##vCenter Compliance Pie Chart
$PieObjectVCCompliance = Get-HTMLPieChartObject
$PieObjectVCCompliance.Title = "vCenter Overall Compliance"
$PieObjectVCCompliance.Size.Height = 250
$PieObjectVCCompliance.Size.Width = 250
$PieObjectVCCompliance.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVCCompliance.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVCCompliance.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVCCompliance.DataDefinition.DataValueColumnName = 'Count'

##vCenter Severity Compliance Pie Chart
$PieObjectVCComplianceSev = Get-HTMLPieChartObject
$PieObjectVCComplianceSev.Title = "vCenter Overall Compliance by Severity"
$PieObjectVCComplianceSev.Size.Height = 250
$PieObjectVCComplianceSev.Size.Width = 250
$PieObjectVCComplianceSev.ChartStyle.ChartType = 'doughnut'
#These file exist in the module directoy, There are 4 schemes by default
$PieObjectVCComplianceSev.ChartStyle.ColorSchemeName = "ColorScheme4"
#Data defintion you can reference any column from name and value from the  dataset.  
#Name and Count are the default to work with the Group function.
$PieObjectVCComplianceSev.DataDefinition.DataNameColumnName = 'Name'
$PieObjectVCComplianceSev.DataDefinition.DataValueColumnName = 'Count'

##Environment Data Table
$envDataTable = New-Object 'System.Collections.Generic.List[System.Object]'
$envData = [PSCustomObject]@{
    'vCenter Server'        = $vcenter
    "ESXi Hosts"	        = ($vmhosts).count
    "Virtual Machines"      = ($vms).count
    "Datastores"	        = ($datastores).count
    "Clusters"              = ($clusters).count
    "Disitrbuted Switches"  = ($vdswitches).count
    }
$envDataTable.Add($envData)


#Generate Report Structure
$report += Get-HtmlOpenPage -TitleText $ReportName -LeftLogoString $CompanyLogo -RightLogoString $RightLogo
$report += Get-HTMLTabHeader -TabNames $tabarray

#Overview Tab
$report += Get-HTMLTabContentopen -TabName $tabarray[0] -TabHeading "vSphere STIG Overview"
$report += Get-HTMLContentOpen -HeaderText "Compliance Overview"
$report += Get-HTMLColumnOpen -ColumnNumber 1 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVMCompliance -DataSet $vmcomptable
$report += Get-HTMLColumnClose
$report += Get-HTMLColumnOpen -ColumnNumber 2 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVMComplianceSev -DataSet $vmcomptablesev
$report += Get-HTMLColumnClose
$report += Get-HTMLColumnOpen -ColumnNumber 3 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVMHostCompliance -DataSet $vmhostcomptable
$report += Get-HTMLColumnClose
$report += Get-HTMLColumnOpen -ColumnNumber 4 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVMHostComplianceSev -DataSet $vmhostcomptablesev
$report += Get-HTMLColumnClose
$report += Get-HTMLColumnOpen -ColumnNumber 5 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVCCompliance -DataSet $vccomptable
$report += Get-HTMLColumnClose
$report += Get-HTMLColumnOpen -ColumnNumber 6 -ColumnCount 6
$report += Get-HTMLPieChart -ChartObject $PieObjectVCComplianceSev -DataSet $vccomptablesev
$report += Get-HTMLColumnClose
$report += Get-HTMLContentClose
$report += Get-HTMLContentOpen -HeaderText "Environment Overview"
$report += Get-HtmlContentDataTable $envDataTable -HideFooter
$report += Get-HTMLContentClose
$report += Get-HTMLTabContentClose

#Virtual Machines Tab
$report += Get-HTMLTabContentopen -TabName $tabarray[1] -TabHeading "vSphere 6.7 Virtual Machine STIG (Version 1 Release 1) Version 1 Release 1"
$report += Get-HtmlContentOpen -HeaderText $vmtitle01
$report += Get-HtmlContentTable $vmsarray01
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle02
$report += Get-HtmlContentTable $vmsarray02
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle03
$report += Get-HtmlContentTable $vmsarray03
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle04
$report += Get-HtmlContentTable $vmsarray04
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle05
$report += Get-HtmlContentTable $vmsarray05
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle06
$report += Get-HtmlContentTable $vmsarray06
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle07
$report += Get-HtmlContentTable $vmsarray07
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle08
$report += Get-HtmlContentTable $vmsarray08
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle09
$report += Get-HtmlContentTable $vmsarray09
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle10
$report += Get-HtmlContentTable $vmsarray10
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle11
$report += Get-HtmlContentTable $vmsarray11
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle12
$report += Get-HtmlContentTable $vmsarray12
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle13
$report += Get-HtmlContentTable $vmsarray13
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle14
$report += Get-HtmlContentTable $vmsarray14
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle15
$report += Get-HtmlContentTable $vmsarray15
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle16
$report += Get-HtmlContentTable $vmsarray16
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle17
$report += Get-HtmlContentTable $vmsarray17
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle18
$report += Get-HtmlContentTable $vmsarray18
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle19
$report += Get-HtmlContentTable $vmsarray19
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle22
$report += Get-HtmlContentTable $vmsarray22
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle23
$report += Get-HtmlContentTable $vmsarray23
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vmtitle24
$report += Get-HtmlContentTable $vmsarray24
$report += Get-HtmlContentClose
$report += Get-HTMLTabContentClose

#ESXi Tab
$report += Get-HTMLTabContentopen -TabName $tabarray[2] -TabHeading "vSphere 6.7 ESXi STIG (Version 1 Release 1) Version 1 Release 1"
$report += Get-HtmlContentOpen -HeaderText $esxititle01
$report += Get-HtmlContentTable $esxiarray01
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle02
$report += Get-HtmlContentTable $esxiarray02
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle03
$report += Get-HtmlContentTable $esxiarray03
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle04
$report += Get-HtmlContentTable $esxiarray04
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle05
$report += Get-HtmlContentTable $esxiarray05
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle06
$report += Get-HtmlContentTable $esxiarray06
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle07
$report += Get-HtmlContentTable $esxiarray07
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle08
$report += Get-HtmlContentTable $esxiarray08
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle09
$report += Get-HtmlContentTable $esxiarray09
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle10
$report += Get-HtmlContentTable $esxiarray10
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle11
$report += Get-HtmlContentTable $esxiarray11
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle12
$report += Get-HtmlContentTable $esxiarray12
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle13
$report += Get-HtmlContentTable $esxiarray13
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle14
$report += Get-HtmlContentTable $esxiarray14
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle15
$report += Get-HtmlContentTable $esxiarray15
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle16
$report += Get-HtmlContentTable $esxiarray16
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle17
$report += Get-HtmlContentTable $esxiarray17
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle18
$report += Get-HtmlContentTable $esxiarray18
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle19
$report += Get-HtmlContentTable $esxiarray19
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle20
$report += Get-HtmlContentTable $esxiarray20
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle21
$report += Get-HtmlContentTable $esxiarray21
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle22
$report += Get-HtmlContentTable $esxiarray22
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle23
$report += Get-HtmlContentTable $esxiarray23
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle24
$report += Get-HtmlContentTable $esxiarray24
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle25
$report += Get-HtmlContentTable $esxiarray25
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle26
$report += Get-HtmlContentTable $esxiarray26
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle27
$report += Get-HtmlContentTable $esxiarray27
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle28
$report += Get-HtmlContentTable $esxiarray28
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle29
$report += Get-HtmlContentTable $esxiarray29
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle30
$report += Get-HtmlContentTable $esxiarray30
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle31
$report += Get-HtmlContentTable $esxiarray31
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle32
$report += Get-HtmlContentTable $esxiarray32
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle33
$report += Get-HtmlContentTable $esxiarray33
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle34
$report += Get-HtmlContentTable $esxiarray34
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle35
$report += Get-HtmlContentTable $esxiarray35
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle36
$report += Get-HtmlContentTable $esxiarray36
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle37
$report += Get-HtmlContentTable $esxiarray37
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle38
$report += Get-HtmlContentTable $esxiarray38
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle39
$report += Get-HtmlContentTable $esxiarray39
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle41
$report += Get-HtmlContentTable $esxiarray41
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle42
$report += Get-HtmlContentTable $esxiarray42
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle43
$report += Get-HtmlContentTable $esxiarray43
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle44
$report += Get-HtmlContentTable $esxiarray44
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle45
$report += Get-HtmlContentTable $esxiarray45
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle46
$report += Get-HtmlContentTable $esxiarray46
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle47
$report += Get-HtmlContentTable $esxiarray47
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle48
$report += Get-HtmlContentTable $esxiarray48
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle49
$report += Get-HtmlContentTable $esxiarray49
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle50
$report += Get-HtmlContentTable $esxiarray50
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle51
$report += Get-HtmlContentTable $esxiarray51
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle52
$report += Get-HtmlContentTable $esxiarray52
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle53
$report += Get-HtmlContentTable $esxiarray53
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle54
$report += Get-HtmlContentTable $esxiarray54
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle55
$report += Get-HtmlContentTable $esxiarray55
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle56
$report += Get-HtmlContentTable $esxiarray56
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle57
$report += Get-HtmlContentTable $esxiarray57
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle58
$report += Get-HtmlContentTable $esxiarray58
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle59
$report += Get-HtmlContentTable $esxiarray59
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle60
$report += Get-HtmlContentTable $esxiarray60
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle61
$report += Get-HtmlContentTable $esxiarray61
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle62
$report += Get-HtmlContentTable $esxiarray62
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle63
$report += Get-HtmlContentTable $esxiarray63
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle64
$report += Get-HtmlContentTable $esxiarray64
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle65
$report += Get-HtmlContentTable $esxiarray65
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle72
$report += Get-HtmlContentTable $esxiarray72
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle74
$report += Get-HtmlContentTable $esxiarray74
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle76
$report += Get-HtmlContentTable $esxiarray76
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle78
$report += Get-HtmlContentTable $esxiarray78
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle79
$report += Get-HtmlContentTable $esxiarray79
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle100004
$report += Get-HtmlContentTable $esxiarray100004
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $esxititle100010
$report += Get-HtmlContentTable $esxiarray100010
$report += Get-HtmlContentClose
$report += Get-HTMLTabContentClose

#vCenter Tab
$report += Get-HTMLTabContentopen -TabName $tabarray[3] -TabHeading "vSphere 6.7 vCenter STIG (Draft) Version 1 Release 1"
$report += Get-HtmlContentOpen -HeaderText $vctitle05
$report += Get-HtmlContentTable $vcarray05
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle07
$report += Get-HtmlContentTable $vcarray07
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle12
$report += Get-HtmlContentTable $vcarray12
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle13
$report += Get-HtmlContentTable $vcarray13
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle14
$report += Get-HtmlContentTable $vcarray14
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle15
$report += Get-HtmlContentTable $vcarray15
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle16
$report += Get-HtmlContentTable $vcarray16
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle17
$report += Get-HtmlContentTable $vcarray17
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle18
$report += Get-HtmlContentTable $vcarray18
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle19
$report += Get-HtmlContentTable $vcarray19
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle20
$report += Get-HtmlContentTable $vcarray20
$report += Get-HtmlContentClose
$report += Get-HtmlContentOpen -HeaderText $vctitle36
$report += Get-HtmlContentTable $vcarray36
$report += Get-HtmlContentClose
$report += Get-HTMLTabContentClose

#Generate Report
$report | Set-Content -Path $ReportFile -Force
Invoke-Item $ReportFile
