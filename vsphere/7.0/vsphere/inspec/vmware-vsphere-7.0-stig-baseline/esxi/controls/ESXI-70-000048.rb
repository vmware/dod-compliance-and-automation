control 'ESXI-70-000048' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.'
  desc  "
    While encrypted vMotion is available, vMotion traffic should still be sequestered from other traffic to futher protect it from attack. This network must be only be accessible to other ESXi hosts preventing outside access to the network.

    The vMotion VMKernel port group must be in a dedicated VLAN that can be on a standard or distributed virtual switch as long as the vMotion VLAN is not shared by any other function and is not routed to anything but ESXi hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESXi, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking and review the VLAN associated with the vMotion VMkernel(s) and verify they are dedicated for that purpose and are logically separated from other functions.

    If long distance or cross vCenter vMotion is used the vMotion network can be routable but must be accessible to only the intended ESXi hosts.

    If the vMotion port group is not on an isolated VLAN and/or is routable to systems other than ESXi hosts, this is a finding.
  "
  desc 'fix', "
    Configuration of the vMotion VMkernel will be unique to each environment.

    As an example, to modify the IP address and VLAN information to the correct network on a distributed switch do the following:

    From the vSphere Client go to Networking >> Select a distributed switch >> Select a port group >> Configure >> Settings >> Edit >> VLAN. Change the \"VLAN Type\" to \"VLAN\" and change the \"VLAN ID\" to a network allocated and dedicated to vMotion traffic exclusively.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000048'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VMotionEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
      vmks = powercli_command(command).stdout

      if vmks.empty?
        describe '' do
          skip 'There are no VMKernel adapters with vMotion enabled so this control is N/A.'
        end
      else
        vmks.split.each do |vmk|
          # Check to see if vMotion and any other services are enabled on the same VMkernel adapter
          command2 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Where-Object {$_.ManagementTrafficEnabled -eq \"True\" -or $_.FaultToleranceLoggingEnabled -eq \"True\" -or $_.VsanTrafficEnabled -eq \"True\" -or $_.VSphereReplicationEnabled -eq \"True\" -or $_.VSphereReplicationNFCEnabled -eq \"True\" -or $_.VSphereBackupNFCEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
          describe powercli_command(command2) do
            its('stdout.strip') { should be_empty }
          end
          # Get vMotion Port Group Name
          command3 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Select-Object -ExpandProperty PortGroupName"
          pgname = powercli_command(command3).stdout.strip
          # Test standard port groups
          command4 = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Name \"#{pgname}\" | Select-Object -ExpandProperty VlanId"
          stdpgs = powercli_command(command4).stdout.strip
          unless stdpgs.empty?
            describe 'Checking standand port group VLAN ID' do
              subject { stdpgs }
              it { should cmp "#{input('vMotionVlanId')}" }
            end
          end
          describe 'SA Interview' do
            skip 'SA also needs to confirm this VLAN is dedicated to vMotion and not routable except to other ESXi hosts.'
          end
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
