control 'VCSA-80-000293' do
  title 'The vCenter server must have task and event retention set to at least 30 days.'
  desc 'vCenter tasks and events contain valuable historical actions, useful in troubleshooting availability issues and for incident forensics. While vCenter events are sent to central log servers in real time, it is important that administrators have quick access to this information when needed.

vCenter retains 30 days of tasks and events by default, and this is sufficient for most purposes. The vCenter disk partitions are also sized with this in mind. Decreasing is not recommended for operational reasons, while increasing is not recommended unless guided by VMware support due to the partition sizing concerns.'
  desc 'check', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click to expand the "Database" section.

Note the "Task retention" and "Event retention" values.

If either value is configured to less than "30" days, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Settings >> General.

Click "Edit".

On the "Database" tab, set the value for both "Task retention" and "Event retention" to "30" days (default) or greater, as required by your site.

Click "Save".'
  impact 0.5
  tag check_id: 'C-62699r934533_chk'
  tag severity: 'medium'
  tag gid: 'V-258959'
  tag rid: 'SV-258959r961863_rule'
  tag stig_id: 'VCSA-80-000293'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62608r934534_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name event.maxAge | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= '30' }
  end
  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name task.maxAge | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= '30' }
  end
end
