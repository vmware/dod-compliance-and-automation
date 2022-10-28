control 'ESXI-70-000031' do
  title 'The ESXi host must be configured with a sufficiently complex password policy.'
  desc  'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.PasswordQualityControl\" value and verify it is set to \"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\"

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

    If the \"Security.PasswordQualityControl\" setting is not set to \"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.PasswordQualityControl\" value and configure it to \"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value \"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-VMM-000360'
  tag satisfies: ['SRG-OS-000070-VMM-000370', 'SRG-OS-000071-VMM-000380', 'SRG-OS-000072-VMM-000390', 'SRG-OS-000078-VMM-000450', 'SRG-OS-000266-VMM-000940']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000031'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (b)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
