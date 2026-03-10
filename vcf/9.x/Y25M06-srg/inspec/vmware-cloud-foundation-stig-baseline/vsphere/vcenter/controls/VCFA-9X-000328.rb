control 'VCFA-9X-000328' do
  title 'The VMware Cloud Foundation vCenter Server must configure the "vpxuser" auto-password to be changed every 30 days.'
  desc  "
    By default, vCenter will change the \"vpxuser\" password automatically every 30 days. Ensure this setting meets site policies. If it does not, configure it to meet password aging policies.

    Note: It is very important the password aging policy is not shorter than the default interval that is set to automatically change the \"vpxuser\" password to preclude the possibility that vCenter might be locked out of an ESXi host.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify the value of the \"VirtualCenter.VimPasswordExpirationInDays\" setting.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays

    If the \"VirtualCenter.VimPasswordExpirationInDays\" is set to a value greater than \"30\" or is set to \"0\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"VirtualCenter.VimPasswordExpirationInDays\" value to \"10\" or if the value does not exist create it by entering the values in the \"Key\" and \"Value\" fields and clicking \"Add\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    If the setting already exists:

    Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays | Set-AdvancedSetting -Value 10

    If the setting does not exist:

    New-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays -Value 10
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000328'
  tag rid: 'SV-VCFA-9X-000328'
  tag stig_id: 'VCFA-9X-000328'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name VirtualCenter.VimPasswordExpirationInDays | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server setting VirtualCenter.VimPasswordExpirationInDays' do
      subject { json(content: result) }
      its(['Value']) { should cmp <= 30 }
      its(['Value']) { should cmp > 0 }
    end
  end
end
