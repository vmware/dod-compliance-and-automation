control 'VCFA-9X-000329' do
  title 'The VMware Cloud Foundation vCenter Server must be configured to send events to a central log server.'
  desc  "
    vCenter server generates volumes of security-relevant application-level events. Examples include logins, system reconfigurations, system degradation warnings, and more. To ensure these events are available for forensic analysis and correlation, they must be sent to the syslog and forwarded on to the configured Security Information and Event Management (SIEM) system and/or central log server.

    The vCenter server sends events to syslog by default, but this configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify that \"vpxd.event.syslog.enabled\" value is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled

    If the \"vpxd.event.syslog.enabled\" value is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"vpxd.event.syslog.enabled\" setting to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000329'
  tag rid: 'SV-VCFA-9X-000329'
  tag stig_id: 'VCFA-9X-000329'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name vpxd.event.syslog.enabled | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server setting vpxd.event.syslog.enabled' do
      subject { json(content: result) }
      its(['Value']) { should cmp 'true' }
    end
  end
end
