# Environment Specific STIG Values
$envstigsettings = [ordered]@{
  indDiskExceptions       = @("") # VCFV-9X-000213 Provide an array of VM names that are approved to have independent non-persistent disks present.
  floppyExceptions        = @("") # VCFV-9X-000214 Provide an array of VM names that are approved to have floppy drives present.
  cddvdExceptions         = @("") # VCFV-9X-000215 Provide an array of VM names that are approved to have CD/DVD drives connected.
  parallelExceptions      = @("") # VCFV-9X-000216 Provide an array of VM names that are approved to have parallel devices present.
  serialExceptions        = @("") # VCFV-9X-000217 Provide an array of VM names that are approved to have serial devices present.
  usbExceptions           = @("") # VCFV-9X-000218 Provide an array of VM names that are approved to have USB devices present.
  passthruExceptions      = @("") # VCFV-9X-000219 Provide an array of VM names that are approved to have passthrough DirectPath I/O devices present.
}

# Enable or Disable specific STIG Rules in your environment
$rulesenabled = [ordered]@{
  VCFV9X000181 = $true  # isolation.tools.copy.disable
  VCFV9X000196 = $true  # isolation.tools.dnd.disable
  VCFV9X000197 = $true  # isolation.tools.paste.disable
  VCFV9X000198 = $true  # isolation.tools.diskShrink.disable
  VCFV9X000199 = $true  # isolation.tools.diskWiper.disable
  VCFV9X000200 = $true  # RemoteDisplay.maxConnections
  VCFV9X000201 = $true  # tools.setinfo.sizeLimit
  VCFV9X000202 = $true  # isolation.device.connectable.disable
  VCFV9X000203 = $true  # tools.guestlib.enableHostInfo
  VCFV9X000204 = $true  # sched.mem.pshare.salt
  VCFV9X000205 = $true  # ethernet*.filter*.name*
  VCFV9X000206 = $true  # tools.guest.desktop.autolock
  VCFV9X000207 = $true  # mks.enable3d
  VCFV9X000208 = $true  # vMotion Encryption
  VCFV9X000209 = $true  # FT Encryption
  VCFV9X000210 = $true  # log.rotateSize
  VCFV9X000211 = $true  # log.keepOld
  VCFV9X000212 = $true  # Enable Logging
  VCFV9X000213 = $true  # Independent Non-Persistent Disks
  VCFV9X000214 = $true  # Floppy Drives
  VCFV9X000215 = $true  # CD/DVD media connected
  VCFV9X000216 = $true  # Parallel
  VCFV9X000217 = $true  # Serial
  VCFV9X000218 = $true  # USB
  VCFV9X000219 = $true  # DirectPath I/O
}

$stigsettings = [ordered]@{
  isoToolsCopyDisable             = @{"isolation.tools.copy.disable"         = $true} # VCFV-9X-000181
  isoToolsDndDisable              = @{"isolation.tools.dnd.disable"          = $true} # VCFV-9X-000196
  isoToolsPasteDisable            = @{"isolation.tools.paste.disable"        = $true} # VCFV-9X-000197
  isoToolsDiskShrinkDisable       = @{"isolation.tools.diskShrink.disable"   = $true} # VCFV-9X-000198
  isoToolsDiskWiperDisable        = @{"isolation.tools.diskWiper.disable"    = $true} # VCFV-9X-000199
  remoteDisplayMaxConn            = @{"RemoteDisplay.maxConnections"         = "1"} # VCFV-9X-000200
  toolsSetinfoSizelimit           = @{"tools.setinfo.sizeLimit"              = "1048576"} # VCFV-9X-000201
  isoDevConnDisable               = @{"isolation.device.connectable.disable" = $true} # VCFV-9X-000202
  toolsGuestlibEnablehostinfo     = @{"tools.guestlib.enableHostInfo"        = $false} # VCFV-9X-000203
  toolsGuestDesktopAutolock       = @{"tools.guest.desktop.autolock"         = $true} # VCFV-9X-000206
  mksEnable3d                     = @{"mks.enable3d"                         = $false} # VCFV-9X-000207
  vmotionEncryption               = "opportunistic" # VCFV-9X-000208 Valid values are: disabled, required, opportunistic
  ftEncryption                    = "ftEncryptionOpportunistic"   # VCFV-9X-000209 Valid values are: ftEncryptionRequired, ftEncryptionOpportunistic
  logRotateSize                   = @{"log.rotateSize"                       = "2048000"} # VCFV-9X-000210
  logKeepOld                      = @{"log.keepOld"                          = "10"} # VCFV-9X-000211
  enableLogging                   = $true # VCFV-9X-000212
}

# OOTB Default Settings and Values
$defaultsettings = [ordered]@{
  isoToolsCopyDisable             = @{"isolation.tools.copy.disable"         = $true} # VCFV-9X-000181
  isoToolsDndDisable              = @{"isolation.tools.dnd.disable"          = $true} # VCFV-9X-000196
  isoToolsPasteDisable            = @{"isolation.tools.paste.disable"        = $true} # VCFV-9X-000197
  isoToolsDiskShrinkDisable       = @{"isolation.tools.diskShrink.disable"   = $true} # VCFV-9X-000198
  isoToolsDiskWiperDisable        = @{"isolation.tools.diskWiper.disable"    = $true} # VCFV-9X-000199
  remoteDisplayMaxConn            = @{"RemoteDisplay.maxConnections"         = "-1"} # VCFV-9X-000200
  toolsSetinfoSizelimit           = @{"tools.setinfo.sizeLimit"              = "1048576"} # VCFV-9X-000201
  isoDevConnDisable               = @{"isolation.device.connectable.disable" = $true} # VCFV-9X-000202
  toolsGuestlibEnablehostinfo     = @{"tools.guestlib.enableHostInfo"        = $false} # VCFV-9X-000203
  toolsGuestDesktopAutolock       = @{"tools.guest.desktop.autolock"         = $true} # VCFV-9X-000206
  mksEnable3d                     = @{"mks.enable3d"                         = $false} # VCFV-9X-000207
  vmotionEncryption               = "opportunistic" # VCFV-9X-000208 Valid values are: disabled, required, opportunistic
  ftEncryption                    = "ftEncryptionOpportunistic"   # VCFV-9X-000209 Valid values are: ftEncryptionRequired, ftEncryptionOpportunistic
  logRotateSize                   = @{"log.rotateSize"                       = "2048000"} # VCFV-9X-000210
  logKeepOld                      = @{"log.keepOld"                          = "10"} # VCFV-9X-000211
  enableLogging                   = $true # VCFV-9X-000212
}
