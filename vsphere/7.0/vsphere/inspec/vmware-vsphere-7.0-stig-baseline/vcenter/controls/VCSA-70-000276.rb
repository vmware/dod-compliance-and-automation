control 'VCSA-70-000276' do
  title 'The vCenter Server must configure the vpxuser password meets length policy.'
  desc  "
    The vpxuser password default length is 32 characters. Ensure this setting meets site policies; if not, configure to meet password length policies.

    Longer passwords make brute-force password attacks more difficult. The vpxuser password is added by vCenter, meaning no manual intervention is normally required. The vpxuser password length must never be modified to less than the default length of 32 characters.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Verify that \"config.vpxd.hostPasswordLength\" is set to \"32\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength and verify it is set to 32.

    If the \"config.vpxd.hostPasswordLength\" is set to a value other than \"32, this is a finding.

    If the setting does not exist, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Settings >> Advanced Settings.

    Click \"Edit Settings\" and configure the \"config.vpxd.hostPasswordLength\" value to \"32\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AdvancedSetting -Entity <vcenter server name> -Name config.vpxd.hostPasswordLength | Set-AdvancedSetting -Value 32
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000276'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name config.vpxd.hostPasswordLength | Select-Object -ExpandProperty Value'
  describe.one do
    describe powercli_command(command) do
      its('stdout.strip') { should cmp '32' }
    end
    describe powercli_command(command) do
      its('stdout.strip') { should be_empty }
    end
  end
end
