control 'VCFE-9X-000042' do
  title 'The ESX host must enforce a 90-day maximum password lifetime restriction.'
  desc  'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the VMM does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the VMM passwords could be compromised.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.PasswordMaxDays\" value and verify it is set to \"90\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays

    If the \"Security.PasswordMaxDays\" setting is not set to \"90\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.PasswordMaxDays\" value and configure it to \"90\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-VMM-000430'
  tag gid: 'V-VCFE-9X-000042'
  tag rid: 'SV-VCFE-9X-000042'
  tag stig_id: 'VCFE-9X-000042'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

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
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.PasswordMaxDays | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '90' }
      end
    end
  end
end
