control 'ESXI-67-000045' do
  title "The ESXi host must enable a persistent log location for all locally
stored logs."
  desc  "ESXi can be configured to store log files on an in-memory file system.
This occurs when the host's \"/scratch\" directory is linked to
\"/tmp/scratch\". When this is done, only a single day's worth of logs is
stored at any time. In addition, log files will be reinitialized upon each
reboot. This presents a security risk as user activity logged on the host is
only stored temporarily and will not persist across reboots. This can also
complicate auditing and make it harder to monitor events and diagnose issues.
ESXi host logging should always be configured to a persistent datastore.

    Note: Scratch space is configured automatically during installation or
first boot of an ESXi host and does not usually need to be manually configured.
ESXi Installable creates a 4 GB Fat16 partition on the target device during
installation if there is sufficient space and if the device is considered
\"local\".

    If ESXi is installed on an SD card or USB device, a persistent log location
may not be configured upon install as normal.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Select the \"Syslog.global.logDir\" value and verify it is set to a
persistent location.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.syslog.config.get.Invoke() | Select
LocalLogOutput,LocalLogOutputIsPersistent

    If the \"LocalLogOutputIsPersistent\" value is not true, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Click \"Edit\" and select the \"Syslog.global.logDir\" value and set it to
a known persistent location.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir |
Set-AdvancedSetting -Value \"New Log Location\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag gid: 'V-239300'
  tag rid: 'SV-239300r674829_rule'
  tag stig_id: 'ESXI-67-000045'
  tag fix_id: 'F-42492r674828_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
