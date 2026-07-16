control 'VCFE-9X-000152' do
  title 'The ESX host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.'
  desc  "
    While encrypted vMotion is available, vMotion traffic should still be sequestered from other traffic to further protect it from attack. This network must only be accessible to other ESX hosts, preventing outside access to the network.

    The vMotion VMkernel port group must be in a dedicated VLAN that can be on a standard or distributed virtual switch as long as the vMotion VLAN is not shared by any other function and is only routed to ESX hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESX, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> VMkernel adapters.

    Review the VLAN associated with any vMotion VMkernel(s) and verify they are dedicated for that purpose and are logically separated from other functions.

    If long distance or cross vCenter vMotion is used, the vMotion network can be routable but must be accessible to only the intended ESX hosts.

    If the vMotion port group is not on an isolated VLAN and/or is routable to systems other than ESX hosts, this is a finding.
  "
  desc 'fix', "
    Configuration of the vMotion VMkernel will be unique to each environment.

    For example, to modify the IP address and VLAN information to the correct network on a distributed switch, do the following:

    From the vSphere Client, go to Networking.

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Properties.

    Click \"Edit\" and select VLAN.

    Change the \"VLAN Type\" to \"VLAN\" and change the \"VLAN ID\" to a network allocated and dedicated to vMotion traffic exclusively. Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: 'V-VCFE-9X-000152'
  tag rid: 'SV-VCFE-9X-000152'
  tag stig_id: 'VCFE-9X-000152'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VMotionEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
      vmks = powercli_command(command).stdout

      if vmks.blank?
        describe '' do
          skip 'There are no VMKernel adapters with vMotion enabled so this control is N/A.'
        end
      else
        vmks.split.each do |vmk|
          # Check to see if vMotion and any other services are enabled on the same VMkernel adapter
          command2 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Where-Object {$_.ManagementTrafficEnabled -eq \"True\" -or $_.FaultToleranceLoggingEnabled -eq \"True\" -or $_.VsanTrafficEnabled -eq \"True\" -or $_.VSphereReplicationEnabled -eq \"True\" -or $_.VSphereReplicationNFCEnabled -eq \"True\" -or $_.VSphereBackupNFCEnabled -eq \"True\"} | Select-Object -ExpandProperty DeviceName"
          describe powercli_command(command2) do
            its('stdout.strip') { should be_blank }
          end
          # Get vMotion Port Group Name
          command3 = "Get-VMHost -Name #{vmhost} | Get-VMHostNetworkAdapter -Name #{vmk} | Select-Object -ExpandProperty PortGroupName"
          pgname = powercli_command(command3).stdout.strip
          # Test standard port groups
          command4 = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Name \"#{pgname}\" -Standard | Select-Object -ExpandProperty VlanId"
          stdpgs = powercli_command(command4).stdout.strip
          unless stdpgs.blank?
            describe 'Checking standand port group VLAN ID' do
              subject { stdpgs }
              it { should cmp "#{input('esx_vmotionVlanId')}" }
            end
          end
          describe 'SA Interview' do
            skip 'SA also needs to confirm this VLAN is dedicated to vMotion and not routable except to other ESXi hosts.'
          end
        end
      end
    end
  end
end
