control 'ESXI-70-000061' do
  title 'All port groups on standard switches must be configured to reject guest promiscuous mode requests.'
  desc  "
    When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup.

    Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. Promiscous mode can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overriden at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the '...' button next to each port group. Click \"View Settings\". Click the \"Policies\" tab. Verify that \"Promiscuous Mode\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VirtualSwitch -Standard | Get-SecurityPolicy
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy

    If the \"Promiscuous Mode\" policy is set to \"Accept\" (or true, via PowerCLI), this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the '...' button next to each port group. Click \"Edit Settings\". Click the \"Security\" tab. Set \"Promiscuous Mode\" to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VirtualSwitch -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000061'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
