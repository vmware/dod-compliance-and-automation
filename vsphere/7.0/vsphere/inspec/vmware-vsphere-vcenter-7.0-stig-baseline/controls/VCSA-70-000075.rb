# encoding: UTF-8

control 'VCSA-70-000075' do
  title "The vCenter server must be configured to send events to a central log
server."
  desc  "vCenter server generates volumes of security-relevant
application-level events. Examples include logins, system reconfigurations,
system degredation warnings, and more. In order to make sure these events are
available for forensic analysis and correlation, those events must be sent to
the syslog forwarded and then on to the configured SIEM and/or central log
server. The vCenter server sends events to syslog by default but this
configuration must be verified and maintained."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server
>> Configure >> Settings >> Advanced Settings. Verify that
\"vpxd.event.syslog.enabled\" value is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server run
the following command:
    Get-AdvancedSetting -Entity <vcenter server name> -Name
vpxd.event.syslog.enabled and verify it is set to \"true\".

    If the \"vpxd.event.syslog.enabled\" value is not set to \"true\", this is
a finding.
  "
  desc  'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server
>> Configure >> Settings >> Advanced Settings. Click \"Edit Settings\" and
configure the \"vpxd.event.syslog.enabled\" setting to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server run
the following command:

    If the setting already exists:
    Get-AdvancedSetting -Entity <vcenter server name> -Name
vpxd.event.syslog.enabled | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000075'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name vpxd.event.syslog.enabled | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "true" }
  end

end

