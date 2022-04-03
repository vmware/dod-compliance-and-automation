control 'ESXI-67-000004' do
  title 'Remote logging for ESXi hosts must be configured.'
  desc  "Remote logging to a central log host provides a secure, centralized
store for ESXi logs. By gathering host log files onto a central host, it can
more easily monitor all hosts with a single tool. It can also do aggregate
analysis and searching to look for such things as coordinated attacks on
multiple hosts. Logging to a secure, centralized log server also helps prevent
log tampering and also provides a long-term audit record.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Select the \"Syslog.global.logHost\" value and verify it is set to a
site-specific syslog server hostname.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

    If the \"Syslog.global.logHost\" setting is not set to a site-specific
syslog server, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Click \"Edit\", select the \"Syslog.global.logHost\" value, and configure
it to a site-specific syslog server.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost |
Set-AdvancedSetting -Value \"<syslog server hostname>\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-VMM-000130'
  tag satisfies: ['SRG-OS-000032-VMM-000130', 'SRG-OS-000342-VMM-001230',
'SRG-OS-000479-VMM-001990']
  tag gid: 'V-239261'
  tag rid: 'SV-239261r674712_rule'
  tag stig_id: 'ESXI-67-000004'
  tag fix_id: 'F-42453r674711_fix'
  tag cci: ['CCI-000067', 'CCI-001851']
  tag nist: ['AC-17 (1)', 'AU-4 (1)']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Syslog.global.logHost | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "#{input('syslogServer')}" }
  end
end
