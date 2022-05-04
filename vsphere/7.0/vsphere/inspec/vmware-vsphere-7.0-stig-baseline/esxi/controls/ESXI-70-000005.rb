control 'ESXI-70-000005' do
  title 'The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Once the configured number of attempts is reached, the account is locked by the ESXi host.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.AccountLockFailures\" value and verify it is set to 3.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

    If \"Security.AccountLockFailures\" setting is set to a value other than 3, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.AccountLockFailures\" value and configure it to 3.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-VMM-000050'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000005'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.AccountLockFailures | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '3' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
