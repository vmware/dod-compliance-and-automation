control 'VCSA-70-000034' do
  title 'The vCenter Server must produce audit records containing information to establish what type of events occurred.'
  desc  'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify that \"config.log.level\" value is set to \"info\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level and verify it is set to \"info\".

    If the \"config.log.level\" value is not set to \"info\" or does not exist, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"config.log.level\" setting to \"info\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000034'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name config.log.level | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'info' }
  end
end
