control 'VCFE-9X-000181' do
  title 'The ESX host must restrict access to the DCUI.'
  desc  "
    Lockdown mode disables direct host access, requiring that administrators manage hosts from vCenter Server. However, if a host becomes isolated from vCenter, the administrator is locked out and can no longer manage the host.

    The \"DCUI.Access\" advanced setting allows specified users to exit lockdown mode in such a scenario. If the Direct Console User Interface (DCUI) is running in strict lockdown mode, this setting is ineffective.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESX, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"DCUI.Access\" value and verify only the root user is listed.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name DCUI.Access and verify it is set to root.

    If the \"DCUI.Access\" is not restricted to \"root\", this is a finding.

    Note: This list is only for local user accounts and should only contain the root user.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"DCUI.Access\" value and configure it to \"root\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value \"root\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000181'
  tag rid: 'SV-VCFE-9X-000181'
  tag stig_id: 'VCFE-9X-000181'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name DCUI.Access | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'root' }
      end
    end
  end
end
