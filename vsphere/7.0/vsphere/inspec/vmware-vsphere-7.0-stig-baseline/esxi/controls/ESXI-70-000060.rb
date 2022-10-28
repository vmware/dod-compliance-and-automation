control 'ESXI-70-000060' do
  title 'All port groups on standard switches must be configured to reject guest MAC address changes.'
  desc  "
    If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

    This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. Reject MAC Changes can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overriden at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the '...' button next to each port group. Click \"View Settings\". Click the \"Policies\" tab. Verify that \"MAC Address Changes\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VirtualSwitch -Standard | Get-SecurityPolicy
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy

    If the \"MAC Address Changes\" policy is set to \"Accept\" (or true, via PowerCLI), this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the '...' button next to each port group. Click \"Edit Settings\". Click the \"Security\" tab. Set \"MAC Address Changes\" to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VirtualSwitch -Standard | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000060'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges"
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
