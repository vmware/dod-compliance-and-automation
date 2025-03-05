control 'ESXI-80-000227' do
  title 'The ESXi host must be configured with an appropriate maximum password age.'
  desc 'The older an ESXi local account password is, the larger the opportunity window is for attackers to guess, crack or reuse a previously cracked password. Rotating passwords on a regular basis is a fundamental security practice and one that ESXi supports.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Security.PasswordMaxDays" value and verify it is set to "90".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays

If the "Security.PasswordMaxDays" setting is not set to "90", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Security.PasswordMaxDays" value and configure it to "90".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90'
  impact 0.5
  tag check_id: 'C-62522r933405_chk'
  tag severity: 'medium'
  tag gid: 'V-258782'
  tag rid: 'SV-258782r959010_rule'
  tag stig_id: 'ESXI-80-000227'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62431r933406_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.PasswordMaxDays | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '90' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
