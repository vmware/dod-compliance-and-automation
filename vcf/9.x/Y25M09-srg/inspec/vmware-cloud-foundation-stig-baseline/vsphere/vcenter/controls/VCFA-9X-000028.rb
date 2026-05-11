control 'VCFA-9X-000028' do
  title 'The VMware Cloud Foundation vCenter Server must produce audit records containing information to establish what type of events occurred.'
  desc  'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify the \"config.log.level\" value is set to \"info\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level and verify it is set to \"info\".

    If the \"config.log.level\" value is not set to \"info\" or does not exist, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"config.log.level\" setting to \"info\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095'
  tag gid: 'V-VCFA-9X-000028'
  tag rid: 'SV-VCFA-9X-000028'
  tag stig_id: 'VCFA-9X-000028'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name config.log.level | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server setting config.log.level' do
      subject { json(content: result) }
      its(['Value']) { should cmp 'info' }
    end
  end
end
