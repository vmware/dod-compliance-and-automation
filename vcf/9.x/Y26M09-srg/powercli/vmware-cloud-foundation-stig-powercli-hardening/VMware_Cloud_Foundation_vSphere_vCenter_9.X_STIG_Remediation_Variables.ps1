# Environment Specific STIG Values
$envstigsettings = [ordered]@{
  ssoDomain                       = "vsphere.local" # Update this is a different SSO domain name was used when deploying vCenter. This is vsphere.local by default.
  ntpServers                      = @("time-a-g.nist.gov","time-b-g.nist.gov") # VCFA-9X-000153 Enter array of NTP servers
  netflowCollectorIp              = "" # VCFA-9X-000326 Enter the authorized NetFlow collector IP if used.
  netflowDisableonallPortGroups   = $true # VCFA-9X-000326 If Netflow is not used disable it on all port groups
  allowedBashAdminUsers           = @() # VCFA-9X-000333 List of allowed users in the SystemConfiguration.BashShellAdministrators SSO group. Administrator and the default service accounts do not need to be listed here.
  allowedBashAdminGroups          = @() # VCFA-9X-000333 List of allowed groups in the SystemConfiguration.BashShellAdministrators SSO group. Empty by default.
  allowedPortMirroringSessions    = @() # VCFA-9X-000340 Enter an array of port mirroring sessions by name that are allowed.
}

# Enable or Disable specific STIG Rules in your environment
$rulesenabled = [ordered]@{
  VCFA9X000004 = $true  # TLS Profile
  VCFA9X000017 = $true  # SSO Max Failed Attempts/Interval
  VCFA9X000018 = $true  # Login Banner
  VCFA9X000028 = $true  # Log Level
  VCFA9X000051 = $true  # Verify Plugins
  VCFA9X000063 = $true  # SSO Password Policy
  VCFA9X000082 = $true  # Session timeout
  VCFA9X000090 = $true  # Verify roles and permissions
  VCFA9X000105 = $true  # Enable NIOC
  VCFA9X000117 = $true  # SSO Account Alarm
  VCFA9X000139 = $true  # SSO Disable auto unlock
  VCFA9X000153 = $true  # NTP
  VCFA9X000191 = $true  # vSAN DAR Encryption
  VCFA9X000252 = $true  # VDS Health Check
  VCFA9X000257 = $true  # SNMP v3
  VCFA9X000270 = $true  # Disable K/B and krbtgt users
  VCFA9X000312 = $true  # Trusted root certificates
  VCFA9X000322 = $true  # Disable SNMP v2
  VCFA9X000323 = $true  # Distributed Port Group Forged Transmits
  VCFA9X000324 = $true  # Distributed Port Group MAC Changes
  VCFA9X000325 = $true  # Distributed Port Group Promiscuous Mode
  VCFA9X000326 = $true  # Netflow collector IP
  VCFA9X000327 = $true  # VLAN Trunking
  VCFA9X000328 = $true  # VirtualCenter.VimPasswordExpirationInDays
  VCFA9X000329 = $true  # vpxd.event.syslog.enabled
  VCFA9X000330 = $true  # vSAN Internet
  VCFA9X000331 = $true  # vSAN iSCSI CHAP
  VCFA9X000332 = $true  # vSAN Key Rotation
  VCFA9X000333 = $true  # SystemConfiguration.BashShellAdministrators
  VCFA9X000334 = $true  # event.maxAge and task.maxAge
  VCFA9X000335 = $true  # Backup NKP with password
  VCFA9X000336 = $true  # Published content library auth
  VCFA9X000337 = $true  # Content library security policy
  VCFA9X000338 = $true  # Separate authN and authZ
  VCFA9X000339 = $true  # Disable CDP/LLDP
  VCFA9X000340 = $true  # Port Mirroring
  VCFA9X000341 = $true  # Port Group Overrides
  VCFA9X000342 = $true  # Reset Port Config
  VCFA9X000343 = $true  # vSAN DIT Encryption
  VCFA9X000344 = $true  # vpxuser password length
  VCFA9X000345 = $true  # MAC Learning Policy
}

# vCenter STIG Settings and Values
$stigsettings = [ordered]@{
  tlsProfile                     = "NIST_2024" # VCFA-9X-000004
  ssoMaxFailedAttempts           = 3 # VCFA-9X-000017
  ssoFailedAttemptIntSec         = 900 # VCFA-9X-000017
  configLogLevel                 = @{"config.log.level" = "info"} # VCFA-9X-000028
  ssoPwPolicyMinLength           = 15 # VCFA-9X-000063
  ssoPwPolicyMaxLength           = 20 # VCFA-9X-000063
  ssoPwPolicyMinLower            = 1 # VCFA-9X-000063
  ssoPwPolicyMinUpper            = 1 # VCFA-9X-000063
  ssoPwPolicyMinNumeric          = 1 # VCFA-9X-000063
  ssoPwPolicyMinSpecial          = 1 # VCFA-9X-000063
  dvsEnableNIOC                  = $true # VCFA-9X-000105
  ssoAutoUnlockIntSec            = 0 # VCFA-9X-000139
  forgedTransmits                = "False" # VCFA-9X-000323
  macChanges                     = "False" # VCFE-9X-000324
  promisciousMode                = "False" # VCFE-9X-000325
  vimPasswordExpirationInDays    = @{"VirtualCenter.VimPasswordExpirationInDays" = 10} # VCFA-9X-000328
  sendEventsSyslog               = @{"vpxd.event.syslog.enabled" = "true"} # VCFA-9X-000329
  eventMaxAge                    = @{"event.maxAge" = "30"} # VCFA-9X-000334
  taskMaxAge                     = @{"event.maxAge" = "30"} # VCFA-9X-000334
  dvsDiscoveryProtocolOperation  = "Disabled" # VCFE-9X-000339
  vpxdPassLength                 = @{"config.vpxd.hostPasswordLength" = "32"} # VCFA-9X-000344
  macLearning                    = $false # VCFE-9X-000345
}

# OOTB Default Settings and Values
$defaultsettings = [ordered]@{
  tlsProfile                     = "COMPATIBLE" # VCFA-9X-000004
  ssoMaxFailedAttempts           = "5" # VCFA-9X-000017
  ssoFailedAttemptIntSec         = "180" # VCFA-9X-000017
  configLogLevel                 = @{"config.log.level" = "info"} # VCFA-9X-000028
  ssoPwPolicyMinLength           = 8 # VCFA-9X-000063
  ssoPwPolicyMaxLength           = 20 # VCFA-9X-000063
  ssoPwPolicyMinLower            = 1 # VCFA-9X-000063
  ssoPwPolicyMinUpper            = 1 # VCFA-9X-000063
  ssoPwPolicyMinNumeric          = 1 # VCFA-9X-000063
  ssoPwPolicyMinSpecial          = 1 # VCFA-9X-000063
  dvsEnableNIOC                  = $true # VCFA-9X-000105  NIOC is enabled by default when dvs created through the UI but not PowerCLI.
  ssoAutoUnlockIntSec            = 300 # VCFA-9X-000139
  forgedTransmits                = "False" # VCFA-9X-000323
  macChanges                     = "False" # VCFE-9X-000324
  promisciousMode                = "False" # VCFE-9X-000325
  netflowDisableonallPortGroups  = $true # VCFA-9X-000326
  vimPasswordExpirationInDays    = @{"VirtualCenter.VimPasswordExpirationInDays" = 10} # VCFA-9X-000328
  sendEventsSyslog               = @{"vpxd.event.syslog.enabled" = "true"} # VCFA-9X-000329
  allowedBashAdminUsers          = @("Administrator") # VCFA-9X-000333
  allowedBashAdminGroups         = @() # VCFA-9X-000333
  eventMaxAge                    = @{"event.maxAge" = "30"} # VCFA-9X-000334
  taskMaxAge                     = @{"event.maxAge" = "30"} # VCFA-9X-000334
  dvsDiscoveryProtocolOperation  = "Listen" # VCFE-9X-000339
  vpxdPassLength                 = @{"config.vpxd.hostPasswordLength" = "32"} # VCFA-9X-000344
  macLearning                    = $false # VCFE-9X-000345
}
