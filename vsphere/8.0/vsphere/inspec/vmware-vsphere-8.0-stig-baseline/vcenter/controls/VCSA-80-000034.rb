control 'VCSA-80-000034' do
  title 'The vCenter Server must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

Verify the "config.log.level" value is set to "info".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level and verify it is set to "info".

If the "config.log.level" value is not set to "info" or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

Click "Edit Settings" and configure the "config.log.level" setting to "info".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info'
  impact 0.5
  tag check_id: 'C-62647r934377_chk'
  tag severity: 'medium'
  tag gid: 'V-258907'
  tag rid: 'SV-258907r934379_rule'
  tag stig_id: 'VCSA-80-000034'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-62556r934378_fix'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name config.log.level | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'info' }
  end
end
