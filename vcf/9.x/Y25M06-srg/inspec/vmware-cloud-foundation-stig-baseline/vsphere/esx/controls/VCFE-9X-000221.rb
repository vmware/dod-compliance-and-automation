control 'VCFE-9X-000221' do
  title 'The ESX host must configure virtual switch security policies to reject promiscuous mode requests.'
  desc  "
    When promiscuous mode is enabled for a virtual switch, all virtual machines (VMs) connected to the Portgroup have the potential to read all packets across that network (only the virtual machines connected to that Portgroup).

    Promiscuous mode is disabled by default on the ESX Server, and this is the recommended setting. Promiscuous mode can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overridden at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    This control addresses ESX standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESX host, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the ellipse (...) button next to each port group and select \"Edit Settings\".

    Click the \"Security\" tab. Verify that \"Promiscuous Mode\" is set to \"Reject\" and that \"Override\" is not checked.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    Get-VirtualSwitch | Get-SecurityPolicy
    Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object *

    If the \"Promiscuous Mode\" policy is set to \"Accept\" (or \"true\", via PowerCLI) or the security policy inherited from the virtual switch is overridden, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click \"Edit\" and select Security.

    Set \"Promiscuous Mode\" to \"Reject\". Click \"OK\".

    For each port group, click the ellipse (...) button and select \"Edit Settings\" then Security.

    Set \"Promiscuous Mode\" to \"Reject\" and uncheck the \"Override\" box. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000221'
  tag rid: 'SV-VCFE-9X-000221'
  tag stig_id: 'VCFE-9X-000221'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualSwitch | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
    end
  end
end
