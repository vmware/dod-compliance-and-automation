control 'VCSA-80-000280' do
  title 'The vCenter server must be configured to send events to a central log server.'
  desc  "
    vCenter server generates volumes of security-relevant application-level events. Examples include logins, system reconfigurations, system degradation warnings, and more. To ensure these events are available for forensic analysis and correlation, they must be sent to the syslog and forwarded on to the configured Security Information and Event Management (SIEM) system and/or central log server.

    The vCenter server sends events to syslog by default, but this configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify that \"vpxd.event.syslog.enabled\" value is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled

    If the \"vpxd.event.syslog.enabled\" value is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"vpxd.event.syslog.enabled\" setting to \"true\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCSA-80-000280'
  tag rid: 'SV-VCSA-80-000280'
  tag stig_id: 'VCSA-80-000280'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name vpxd.event.syslog.enabled | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
