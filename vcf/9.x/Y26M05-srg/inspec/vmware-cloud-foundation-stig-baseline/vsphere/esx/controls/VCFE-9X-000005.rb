control 'VCFE-9X-000005' do
  title 'The ESX host must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized VMM access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account. This restriction may be relaxed for administrative accounts to avoid potential Denial of Service.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.AccountLockFailures\" value and verify it is set to \"3\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

    If the \"Security.AccountLockFailures\" setting is set to a value other than \"3\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.AccountLockFailures\" value and configure it to \"3\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-VMM-000050'
  tag gid: 'V-VCFE-9X-000005'
  tag rid: 'SV-VCFE-9X-000005'
  tag stig_id: 'VCFE-9X-000005'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    advSettingName = 'Security.AccountLockFailures'
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name '#{vmhost}' | Get-AdvancedSetting -Name #{advSettingName} | Select-Object Name,Value,Entity | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      describe "The setting: #{advSettingName} on ESX Host: #{vmhost}" do
        subject { json(content: result) }
        its(['Value']) { should cmp 3 }
      end
    end
  end
end
