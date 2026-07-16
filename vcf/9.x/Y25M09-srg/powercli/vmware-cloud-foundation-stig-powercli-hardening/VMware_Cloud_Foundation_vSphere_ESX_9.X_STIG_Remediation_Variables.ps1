# Environment Specific STIG Values
$envstigsettings = [ordered]@{
  ntpServers              = @() # VCFE-9X-000121 Array of authorized NTP servers
  issueBanner             = @{"Config.Etc.issue" = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."} # VCFE-9X-000196
  lockdownExceptionUsers  = @() # VCFE-9X-000205 Note da-user,nsx-user,mux_user and the vcf-svc-* account user will be added for each host. Only add an environment specific users here.
  allowedips              = @() # VCFE-9X-000217 Allows IP ranges for the ESX firewall. Enter a comma separated list, for example: @("10.0.0.0/8","172.16.0.0/16")
  esxAdminsGroup          = "" # VCFE-9X-000239 Enter your environment specific AD group here if hosts are joined to AD and this capability is used.
}

# Enable or Disable specific STIG Rules in your environment
$rulesenabled = [ordered]@{
  VCFE9X000005 = $true  # Account Lock Failures
  VCFE9X000006 = $true  # Consent Banner Welcome
  VCFE9X000008 = $true  # Lockdown Mode
  VCFE9X000010 = $true  # Host Client Timeout
  VCFE9X000014 = $true  # TLS Profile
  VCFE9X000015 = $true  # Log Level
  VCFE9X000035 = $true  # Password Complexity
  VCFE9X000042 = $true  # Password Max Days
  VCFE9X000046 = $true  # Disable MOB
  VCFE9X000048 = $true  # Active Directory
  VCFE9X000064 = $true  # Memory Salting
  VCFE9X000066 = $true  # Shell Interactive Timeout
  VCFE9X000082 = $true  # Secure boot enforcement
  VCFE9X000091 = $true  # Secure boot
  VCFE9X000096 = $true  # SSH Disabled
  VCFE9X000108 = $true  # Account Unlock Time
  VCFE9X000110 = $true  # Audit Storage Capacity
  VCFE9X000111 = $true  # Audit Record Remote
  VCFE9X000121 = $true  # NTP
  VCFE9X000130 = $true  # Acceptance Level
  VCFE9X000138 = $true  # iSCSI CHAP
  VCFE9X000152 = $true  # Isolate vMotion
  VCFE9X000181 = $true  # DCUI Access
  VCFE9X000193 = $true  # TPM Config encryption
  VCFE9X000196 = $true  # etc issue
  VCFE9X000197 = $true  # SSH Banner
  VCFE9X000198 = $true  # Enable Audit Records
  VCFE9X000199 = $true  # Shell Disabled
  VCFE9X000200 = $true  # Shell Timeout
  VCFE9X000201 = $true  # DCUI Timeout
  VCFE9X000202 = $true  # Syslog Log Dir
  VCFE9X000203 = $true  # Management Isolation
  VCFE9X000204 = $true  # IP Storage Isolation
  VCFE9X000205 = $true  # Lockdown Mode Exceptions
  VCFE9X000206 = $true  # SSH ciphers
  VCFE9X000207 = $true  # SSH GatewayPorts
  VCFE9X000208 = $true  # SSH PermitUserEnvironment
  VCFE9X000209 = $true  # SSH PermitTunnel
  VCFE9X000210 = $true  # SSH ClientAliveCountMax
  VCFE9X000211 = $true  # SSH ClientAliveInterval
  VCFE9X000212 = $true  # SSH AllowTCPForwarding
  VCFE9X000213 = $true  # SSH IgnoreRhosts
  VCFE9X000214 = $true  # SSH HostbasedAuthentication
  VCFE9X000215 = $true  # Disable SNMP v1/v2c
  VCFE9X000216 = $true  # Default Firewall
  VCFE9X000217 = $true  # Firewall Rules
  VCFE9X000218 = $true  # BlockGuestBPDU
  VCFE9X000219 = $true  # Forged Transmits
  VCFE9X000220 = $true  # MAC Changes
  VCFE9X000221 = $true  # Promiscious Mode
  VCFE9X000222 = $true  # dvFilter
  VCFE9X000223 = $true  # Virtual Guest Tagging
  VCFE9X000224 = $true  # Suppress Shell Warning
  VCFE9X000225 = $true  # Mem eagerzero
  VCFE9X000226 = $true  # SOAP API Timeout
  VCFE9X000227 = $true  # Suppress Hyperthreading Warning
  VCFE9X000228 = $true  # execInstalledOnly
  VCFE9X000229 = $true  # execInstalledOnly enforcement
  VCFE9X000230 = $true  # Syslog x509 strict
  VCFE9X000232 = $true  # /etc/vmware/settings
  VCFE9X000233 = $true  # /etc/vmware/config
  VCFE9X000234 = $true  # entropy
  VCFE9X000235 = $true  # log filtering
  VCFE9X000236 = $true  # disable key persistence
  VCFE9X000237 = $true  # dcui shell access
  VCFE9X000238 = $true  # BMCNetwork
  VCFE9X000239 = $true  # AD group
  VCFE9X000240 = $true  # AD group auto add
  VCFE9X000241 = $true  # AD group validate
}

# ESX STIG Settings and Values
$stigsettings = [ordered]@{
  accountLockFailures     = @{"Security.AccountLockFailures" = "3"} # VCFE-9X-000005
  lockdownlevel           = "lockdownNormal"  # VCFE-9X-000008	lockdownDisabled,lockdownNormal,lockdownStrict
  hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "900"} # VCFE-9X-000010
  tlsServerProfile        = "NIST_2024" # VCFE-9X-000014
  logLevel                = @{"Config.HostAgent.log.level" = "info"} # VCFE-9X-000015
  passwordComplexity      = @{"Security.PasswordQualityControl" = "random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} # VCFE-9X-000035
  passwordMaxDays         = @{"Security.PasswordMaxDays" = "90"} # VCFE-9X-000042
  enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} # VCFE-9X-000046
  shareForceSalting       = @{"Mem.ShareForceSalting" = "2"} # VCFE-9X-000064
  shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "900"} # VCFE-9X-000066
  secureBootEnforcement   = $true # VCFE-9X-000082
  uefiSecureBoot          = $true # VCFE-9X-000091
  serviceSshEnabled       = $false # VCFE-9X-000096
  serviceSshPolicy        = "off" # VCFE-9X-000096
  accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} # VCFE-9X-000108
  auditRecordStorageCap   = @{"Syslog.global.auditRecord.storageCapacity" = "100"} # VCFE-9X-000110
  auditRecordRemote       = @{"Syslog.global.auditRecord.remoteEnable" = $true} # VCFE-9X-000111
  usePtpForTime           = $false # VCFE-9X-000121
  serviceNtpEnabled       = $true # VCFE-9X-000121
  serviceNtpPolicy        = "on" # VCFE-9X-000121
  vibacceptlevel          = "PartnerSupported"  # VCFE-9X-000130 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
  dcuiAccess              = @{"DCUI.Access" = "root"}  # VCFE-9X-000181
  tpmConfigEncryption     = "TPM"  # VCFE-9X-000193
  sshBanner               = @{"banner" = "/etc/issue"} # VCFE-9X-000197
  syslogAuditEnable       = @{"Syslog.global.auditRecord.storageEnable" = $true} # VCFE-9X-000198
  serviceShellEnabled     = $false # VCFE-9X-000199
  serviceShellPolicy      = "off" # VCFE-9X-000199
  shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"} # VCFE-9X-000200
  dcuiTimeout             = @{"UserVars.DcuiTimeOut" = "600"} # VCFE-9X-000201
  sshCiphers              = @{"ciphers" = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"} # VCFE-9X-000206
  sshGatewayports         = @{"gatewayports" = "no"} # VCFE-9X-000207
  sshPermituserenv        = @{"permituserenvironment" = "no"} # VCFE-9X-000208
  sshPermittunnel         = @{"permittunnel" = "no"} # VCFE-9X-000209
  sshClientalivecountmax  = @{"clientalivecountmax" = "3"} # VCFE-9X-000210
  sshClientaliveinterval  = @{"clientaliveinterval" = "200"} # VCFE-9X-000211
  sshAllowtcpforwarding   = @{"allowtcpforwarding" = "no"} # VCFE-9X-000212
  sshIgnorerhosts         = @{"ignorerhosts" = "yes"} # VCFE-9X-000213
  sshHostbasedauth        = @{"hostbasedauthentication" = "no"} # VCFE-9X-000214
  firewallDefaultAction   = $false # VCFE-9X-000216 false = DROP true = ALLOW
  firewallDefaultEnable   = $true # VCFE-9X-000216
  blockGuestBpdu          = @{"Net.BlockGuestBPDU" = "1"} # VCFE-9X-000218
  forgedTransmits         = $false # VCFE-9X-000219
  forgedTransmitsInherit  = $false # VCFE-9X-000219
  macChanges              = $false # VCFE-9X-000220
  macChangesInherit       = $false # VCFE-9X-000220
  promisciousMode         = $false # VCFE-9X-000221
  promisciousModeInherit  = $false # VCFE-9X-000221
  dvFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} # VCFE-9X-000222
  suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} # VCFE-9X-000224
  memEagerZero            = @{"Mem.MemEagerZero" = "1"} # VCFE-9X-000225
  apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} # VCFE-9X-000226
  suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} # VCFE-9X-000227
  execInstalledOnly       = @{"VMkernel.Boot.execInstalledOnly" = "true"} # VCFE-9X-000228
  execInstallEnforcement  = $true # VCFE-9X-000229
  syslogCertStrict        = @{"Syslog.global.certificate.strictX509Compliance" = $true} # VCFE-9X-000230
  disableHwrng            = "FALSE" # VCFE-9X-000234
  entropySources          = "0" # VCFE-9X-000234
  logFilteringEnabled     = $false # VCFE-9X-000235
  disableKeyPersistence   = $true # VCFE-9X-000236
  dcuiShellAccess         = "false" # VCFE-9X-000237
  bmcNetworkEnable        = @{"Net.BMCNetworkEnable" = 0} # VCFE-9X-000238
  esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = ""} # VCFE-9X-000239
  esxAdminsGroupAutoAdd   = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd" = $false} # VCFE-9X-000240
  authValidateInterval    = @{"Config.HostAgent.plugins.vimsvc.authValidateInterval" = 90} # VCFE-9X-000241
}

# VCFE-9X-000005
$welcomeBanner = @"
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:         {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      enforcement (LE), and counterintelligence (CI) investigations.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     At any time, the USG may inspect and seize data stored on this IS.                        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Communications using, or data stored on, this IS are not private, are subject to routine monitoring,      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      interception, and search, and may be disclosed or used for any USG-authorized purpose.              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not   {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      for your personal benefit or privacy.                                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -     Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}      product are private and confidential. See User Agreement for details.                       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}  
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                              {/color}{/bgcolor}
"@

# OOTB Default Settings and Values
$defaultsettings = [ordered]@{
  accountLockFailures     = @{"Security.AccountLockFailures" = "0"} # VCFE-9X-000005
  welcomeBanner           = @{"Annotations.WelcomeMessage" = ""} # VCFE-9X-000006
  lockdownlevel           = "lockdownDisabled"  # VCFE-9X-000008
  hostClientTimeout       = @{"UserVars.HostClientSessionTimeout" = "900"} # VCFE-9X-000010
  tlsServerProfile        = "COMPATIBLE" # VCFE-9X-000014
  logLevel                = @{"Config.HostAgent.log.level" = "info"} # VCFE-9X-000015
  passwordComplexity      = @{"Security.PasswordQualityControl" = "random=0 retry=3 min=disabled,disabled,disabled,7,7"} # VCFE-9X-000035
  passwordMaxDays         = @{"Security.PasswordMaxDays" = "99999"} # VCFE-9X-000042
  enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = $false} # VCFE-9X-000046
  shareForceSalting       = @{"Mem.ShareForceSalting" = "2"} # VCFE-9X-000064
  shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "0"} # VCFE-9X-000066
  secureBootEnforcement   = $true # VCFE-9X-000082
  uefiSecureBoot          = $true # VCFE-9X-000091
  serviceSshEnabled       = $true # VCFE-9X-000096
  serviceSshPolicy        = "on" # VCFE-9X-000096
  accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"} # VCFE-9X-000108
  auditRecordStorageCap   = @{"Syslog.global.auditRecord.storageCapacity" = "4"} # VCFE-9X-000110
  auditRecordRemote       = @{"Syslog.global.auditRecord.remoteEnable" = $false} # VCFE-9X-000111
  ntpServers              = @() # VCFE-9X-000121
  usePtpForTime           = $false # VCFE-9X-000121
  serviceNtpEnabled       = $true # VCFE-9X-000121
  serviceNtpPolicy        = "on" # VCFE-9X-000121
  vibacceptlevel          = "PartnerSupported"  # VCFE-9X-000130 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
  dcuiAccess              = @{"DCUI.Access" = "root"}  # VCFE-9X-000181
  issueBanner             = @{"Config.Etc.issue" = ""} # VCFE-9X-000196
  sshBanner               = @{"banner" = "/etc/issue"} # VCFE-9X-000197
  syslogAuditEnable       = @{"Syslog.global.auditRecord.storageEnable" = $false} # VCFE-9X-000198
  serviceShellEnabled     = $false # VCFE-9X-000199
  serviceShellPolicy      = "off" # VCFE-9X-000199
  shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "0"} # VCFE-9X-000200
  dcuiTimeout             = @{"UserVars.DcuiTimeOut" = "600"} # VCFE-9X-000201
  sshCiphers              = @{"ciphers" = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"} # VCFE-9X-000206
  sshGatewayports         = @{"gatewayports" = "no"} # VCFE-9X-000207
  sshPermituserenv        = @{"permituserenvironment" = "no"} # VCFE-9X-000208
  sshPermittunnel         = @{"permittunnel" = "no"} # VCFE-9X-000209
  sshClientalivecountmax  = @{"clientalivecountmax" = "3"} # VCFE-9X-000210
  sshClientaliveinterval  = @{"clientaliveinterval" = "200"} # VCFE-9X-000211
  sshAllowtcpforwarding   = @{"allowtcpforwarding" = "no"} # VCFE-9X-000212
  sshIgnorerhosts         = @{"ignorerhosts" = "yes"} # VCFE-9X-000213
  sshHostbasedauth        = @{"hostbasedauthentication" = "no"} # VCFE-9X-000214
  firewallDefaultAction   = $false # VCFE-9X-000216 false = DROP true = ALLOW
  firewallDefaultEnable   = $true # VCFE-9X-000216
  blockGuestBpdu          = @{"Net.BlockGuestBPDU" = "0"} # VCFE-9X-000218
  forgedTransmits         = $false # VCFE-9X-000219
  forgedTransmitsInherit  = $false # VCFE-9X-000219
  macChanges              = $false # VCFE-9X-000220
  macChangesInherit       = $false # VCFE-9X-000220
  promisciousMode         = $false # VCFE-9X-000221
  promisciousModeInherit  = $false # VCFE-9X-000221
  dvFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress" = ""} # VCFE-9X-000222
  suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"} # VCFE-9X-000224
  memEagerZero            = @{"Mem.MemEagerZero" = "0"} # VCFE-9X-000225
  apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} # VCFE-9X-000226
  suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"} # VCFE-9X-000227
  execInstalledOnly       = @{"VMkernel.Boot.execInstalledOnly" = "true"} # VCFE-9X-000228
  execInstallEnforcement  = $true # VCFE-9X-000229
  syslogCertStrict        = @{"Syslog.global.certificate.strictX509Compliance" = $false} # VCFE-9X-000230
  disableHwrng            = "FALSE" # VCFE-9X-000234
  entropySources          = "0" # VCFE-9X-000234
  logFilteringEnabled     = $false # VCFE-9X-000235
  disableKeyPersistence   = $true # VCFE-9X-000236
  dcuiShellAccess         = "true" # VCFE-9X-000237
  bmcNetworkEnable        = @{"Net.BMCNetworkEnable" = 1} # VCFE-9X-000238
  esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = "ESX Admins"} # VCFE-9X-000239
  esxAdminsGroupAutoAdd   = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd" = $false} # VCFE-9X-000240
  authValidateInterval    = @{"Config.HostAgent.plugins.vimsvc.authValidateInterval" = 90} # VCFE-9X-000241
}
