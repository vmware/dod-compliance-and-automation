control 'VCFA-9X-000334' do
  title 'The VMware Cloud Foundation vCenter server must have task and event retention set to at least 30 days.'
  desc  "
    vCenter tasks and events contain valuable historical actions, useful in troubleshooting availability issues and for incident forensics. While vCenter events are sent to central log servers in real time, it is important that administrators have quick access to this information when needed.

    vCenter retains 30 days of tasks and events by default, and this is sufficient for most purposes. The vCenter disk partitions are also sized with this in mind. Decreasing is not recommended for operational reasons, while increasing is not recommended unless guided by VMware support due to the partition sizing concerns.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> General.

    Click to expand the \"Database\" section.

    Note the \"Task retention\" and \"Event retention\" values.

    If either value is configured to less than \"30\" days, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> General.

    Click \"Edit\".

    On the \"Database\" tab, set the value for both \"Task retention\" and \"Event retention\" to \"30\" days (default) or greater, as required by your site.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000334'
  tag rid: 'SV-VCFA-9X-000334'
  tag stig_id: 'VCFA-9X-000334'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name event.maxAge | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server setting event.maxAge' do
      subject { json(content: result) }
      its(['Value']) { should cmp >= 30 }
    end
  end

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name task.maxAge | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server setting task.maxAge' do
      subject { json(content: result) }
      its(['Value']) { should cmp >= 30 }
    end
  end
end
