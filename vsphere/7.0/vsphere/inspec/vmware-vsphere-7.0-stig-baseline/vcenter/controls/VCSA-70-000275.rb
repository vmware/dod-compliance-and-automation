control 'VCSA-70-000275' do
  title 'The vCenter Server must configure the vpxuser auto-password to be changed every 30 days.'
  desc  "
    By default, the vpxuser password will be automatically changed by vCenter every 30 days. Ensure this setting meets site policies; if not, configure to meet password aging policies.

    Note: It is very important the password aging policy not be shorter than the default interval that is set to automatically change the vpxuser password, to preclude the possibility that vCenter might be locked out of an ESXi host.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify that \"VirtualCenter.VimPasswordExpirationInDays\" is set to \"30\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays

    If the \"VirtualCenter.VimPasswordExpirationInDays\" is set to a value other than \"30\" or does not exist, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"VirtualCenter.VimPasswordExpirationInDays\" value to \"30\" or if the value does not exist create it by entering the values in the \"Key\" and \"Value\" fields and clicking \"Add\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    If the setting already exists:

    Get-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays | Set-AdvancedSetting -Value 30

    If the setting does not exist:

    New-AdvancedSetting -Entity <vcenter server name> -Name VirtualCenter.VimPasswordExpirationInDays -Value 30
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000275'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name VirtualCenter.VimPasswordExpirationInDays | Select-Object -ExpandProperty Value'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '30' }
  end
end
