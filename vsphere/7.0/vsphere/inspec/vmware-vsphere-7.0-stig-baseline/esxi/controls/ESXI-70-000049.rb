control 'ESXI-70-000049' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic.'
  desc  "
    The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.

    The Management VMkernel port group can be on a standard or distributed virtual switch but must be on a dedicated VLAN. The Management VLAN must not be shared by any other function and must not be accessible to anything other than management related functions such as vCenter.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

    Select each VMkernel adapter that is \"Enabled\" for management traffic and, in the bottom pane, view the \"Enabled services\".

    If there are any services enabled on any Management VMkernel adapter, this is a finding.

    From the vSphere Client select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

    Review the VLAN associated with each VMkernel that is \"Enabled\" for management traffic. Verify with the SA that they are dedicated for that purpose and are logically separated from other functions.

    If the network segment is accessible, except to networks where other management-related entities are located such as vCenter, this is a finding.

    If there are any other systems or devices such as virtual machines on the ESXi management segment, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> VMkernel adapters.

    Select the Management VMkernel and click \"Edit...\". On the Port properties tab, uncheck all services except for \"Management\". Click \"OK\".

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    Find the port group that contains the Management VMkernel and click the '...' button next to the name. Click \"Edit Settings\".

    On the \"Properties\" tab, change the \"VLAN ID\" to one dedicated to Management traffic. Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000049'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.ManagementTrafficEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
      vmks = powercli_command(command).stdout

      vmks.split.each do |vmk|
        # Check to see if Management and any other services are enabled on the same VMkernel adapter
        command2 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Where-Object {(($_.ManagementTrafficEnabled -eq \"True\" -and $_.FaultToleranceLoggingEnabled -eq \"True\") -xor ($_.VMotionEnabled -eq \"True\" -and $_.ManagementTrafficEnabled -eq \"True\") -xor ($_.ManagementTrafficEnabled -eq \"True\" -and $_.VsanTrafficEnabled -eq \"True\"))} | Select-Object -ExpandProperty DeviceName"
        describe powercli_command(command2) do
          its('stdout.strip') { should be_empty }
        end
        # Get Management Port Group Name
        command3 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Select-Object -ExpandProperty PortGroupName"
        pgname = powercli_command(command3).stdout.strip
        # Test standard port groups
        command4 = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Name \"#{pgname}\" | Select-Object -ExpandProperty VlanId"
        stdpgs = powercli_command(command4).stdout.strip
        unless stdpgs.empty?
          describe 'Checking standand port group VLAN ID' do
            subject { stdpgs }
            it { should cmp "#{input('mgtVlanId')}" }
          end
        end
        describe 'SA Interview' do
          skip 'SA also needs to confirm this VLAN is dedicated to Management and not shared with VMs or other services.'
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
