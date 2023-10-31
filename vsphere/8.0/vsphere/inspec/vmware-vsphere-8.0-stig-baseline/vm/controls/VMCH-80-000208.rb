control 'VMCH-80-000208' do
  title 'Virtual machines (VMs) must not use independent, nonpersistent disks.'
  desc  "
    The security issue with nonpersistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, ensure activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.

    There can be valid use cases for these types of disks, such as with an application presentation solution where read-only disks are desired, and such cases should be identified and documented.
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Review the attached hard disks and verify they are not configured as independent nonpersistent disks.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence | FT -AutoSize

    If the virtual machine has attached disks that are in independent nonpersistent mode and are not documented, this is a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Select the target hard disk and change the mode to persistent or uncheck Independent.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run one of the following commands:

    Get-VM \"VM Name\" | Get-HardDisk | Set-HardDisk -Persistence IndependentPersistent

    or

    Get-VM \"VM Name\" | Get-HardDisk | Set-HardDisk -Persistence Persistent
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000208'
  tag rid: 'SV-VMCH-80-000208'
  tag stig_id: 'VMCH-80-000208'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if !vms.empty?
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-HardDisk | Select-Object -ExpandProperty Persistence"
      results = powercli_command(command)
      results.stdout.split.each do |disk|
        describe "Checking the VM: #{vm} for Non-Persistent Hard Disks" do
          subject { disk }
          it { should_not cmp 'IndependentNonPersistent' }
        end
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
