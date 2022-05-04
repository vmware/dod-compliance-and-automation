control 'ESXI-70-000006' do
  title 'The ESXi host must enforce an unlock timeout of 15 minutes after a user account is locked out.'
  desc  'By enforcing a reasonable unlock timeout after multiple failed logon attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Users must wait for the timeout period to elapse before subsequent logon attempts are allowed.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.AccountUnlockTime\" value and verify it is set to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime

    If the \"Security.AccountUnlockTime\" setting is set to a value other than 900, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.AccountUnlockTime\" value and configure it to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-VMM-001180'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000006'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.AccountUnlockTime | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '900' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
