control 'VCFE-9X-000035' do
  title 'The ESX host must enforce password complexity by configuring a password quality policy.'
  desc  "
    To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.

    The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Security.PasswordQualityControl\" value and verify it is set to \"random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

    If the \"Security.PasswordQualityControl\" setting is set to a value other than \"random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Security.PasswordQualityControl\" value and configure it to \"random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value \"random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-VMM-000360'
  tag satisfies: ['SRG-OS-000070-VMM-000370', 'SRG-OS-000071-VMM-000380', 'SRG-OS-000072-VMM-000390', 'SRG-OS-000078-VMM-000450', 'SRG-OS-000266-VMM-000940']
  tag gid: 'V-VCFE-9X-000035'
  tag rid: 'SV-VCFE-9X-000035'
  tag stig_id: 'VCFE-9X-000035'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15' }
      end
    end
  end
end
