control 'ESXI-70-000059' do
  title 'All port groups on standard switches must be configured to reject forged transmits.'
  desc  "
    If the virtual machine (VM) operating system changes the Media Access Control (MAC) address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

    This means the virtual switch does not compare the source and effective MAC addresses.

    To protect against MAC address impersonation, all virtual switches must have forged transmissions set to reject. Reject Forged Transmit can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overridden at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the \"...\" button next to each port group. Click View Settings >> Policies tab.

    Verify that \"Forged transmits\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    Get-VirtualSwitch -Standard | Get-SecurityPolicy
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy

    If the \"Forged Transmits\" policy is set to \"Accept\" (or \"true\", via PowerCLI), this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

    On each standard switch, click the \"...\" button next to each port group. Click Edit Settings >> Security tab.

    Set \"Forged transmits\" to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    Get-VirtualSwitch -Standard | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false
    Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256420'
  tag rid: 'SV-256420r886041_rule'
  tag stig_id: 'ESXI-70-000059'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualSwitch -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
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
