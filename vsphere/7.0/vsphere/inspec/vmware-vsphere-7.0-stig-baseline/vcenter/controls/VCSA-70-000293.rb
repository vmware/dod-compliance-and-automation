control 'VCSA-70-000293' do
  title 'vCenter task and event retention must be set to at least 30 days.'
  desc  "
    vCenter tasks and events contain valuable historical actions, useful in troubleshooting availability issues and for incident forensics. While vCenter events are sent to central log servers in real time, it is important that administrators have quick access to this information when needed.

    vCenter retains 30 days of tasks and events by default and this is sufficient for most purposes. The vCenter disk partitions are also sized with this in minds. Decreasing is not recommended for operational reasons while increasing is not recommended unless guided by VMware support, due to the partition sizing concerns.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> General.

    Click to expand the \"Database\" section.

    Note the \"Task retention\" and \"Event retention\" values.

    If either value is configured to less than \"30\" days, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\".

    On the \"Database\" tab, set the value for both \"Task retention\" and \"Event retention\" to \"30\" days (default) or greater, as required by your site.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000293'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name event.maxAge | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '30' }
  end
  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name task.maxAge | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '30' }
  end
end
