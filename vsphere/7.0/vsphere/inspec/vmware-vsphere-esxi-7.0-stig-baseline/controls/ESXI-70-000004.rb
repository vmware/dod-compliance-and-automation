control 'ESXI-70-000004' do
  title 'Remote logging for ESXi hosts must be configured.'
  desc  "Remote logging to a central log host provides a secure, centralized
store for ESXi logs. By gathering host log files onto a central host it can
more easily monitor all hosts with a single tool. It can also do aggregate
analysis and searching to look for such things as coordinated attacks on
multiple hosts. Logging to a secure, centralized log server also helps prevent
log tampering and also provides a long-term audit record."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Syslog.global.logHost\" value and verify it is set to a site specific syslog
server. Follow the following conventions:

    udp://<IP/FQDN>:514
    tcp://<IP/FQDN>:514
    ssl://<IP/FQDN>:1514

    Multiple servers can be specified when separated by commas.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

    If the \"Syslog.global.logHost\" setting is not set to a valid, site
specific syslog server, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Click \"Edit\". Select the
\"Syslog.global.logHost\" value and configure it to a site specific syslog
server.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost |
Set-AdvancedSetting -Value \"<syslog server hostname>\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-VMM-000130'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000004'
  tag fix_id: nil
  tag cci: 'CCI-000067'
  tag nist: ['AC-17 (1)']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Syslog.global.logHost | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "#{input('syslogServer')}" }
  end
end
