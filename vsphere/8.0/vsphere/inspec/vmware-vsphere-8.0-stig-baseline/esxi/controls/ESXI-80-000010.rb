control 'ESXI-80-000010' do
  title 'The ESXi host client must be configured with an idle session timeout.'
  desc  'The ESXi host client is the UI served up by the host itself, outside of vCenter. It is accessed by browsing to "https://<ESX FQDN>/ui". ESXi is not usually administered via this interface for long periods and all users will be highly privileged. Implementing a mandatory session idle limit will ensure that orphaned, forgotten or ignored sessions will be closed promptly.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.HostClientSessionTimeout\" value and verify it is set to \"900\" or less.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout

    If the \"UserVars.HostClientSessionTimeout\" setting is not set to \"900\" or less, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.HostClientSessionTimeout\" value and configure it to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value \"900\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-VMM-000100'
  tag gid: 'V-ESXI-80-000010'
  tag rid: 'SV-ESXI-80-000010'
  tag stig_id: 'ESXI-80-000010'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 900 }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
