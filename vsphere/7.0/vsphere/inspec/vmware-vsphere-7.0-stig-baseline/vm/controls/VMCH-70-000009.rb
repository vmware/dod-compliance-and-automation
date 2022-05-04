control 'VMCH-70-000009' do
  title 'Unauthorized CD/DVD devices must be disconnected on the virtual machine.'
  desc  'Ensure that no device is connected to a virtual machine if it is not required. For example, floppy, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings.

    Review the VMs hardware and verify no CD/DVD drives are connected.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true} | Select Parent,Name

    If a virtual machine has a CD/DVD drive connected other than temporarily, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings.

    Select the CD/DVD drive and uncheck \"Connected\" and \"Connect at power on\" and remove any attached ISOs..

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-CDDrive | Set-CDDrive -NoMedia
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000009'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vms.empty?
    vms.each do |vm|
      command = "(Get-VM -Name #{vm} | Get-CDDrive).ExtensionData.connectable.connected"
      results = powercli_command(command).stdout.strip
      describe.one do
        describe 'Checking the VM for connected CD/DVD drives' do
          subject { results }
          it { should cmp 'False' }
        end
        describe 'Checking the VM for connected CD/DVD drives' do
          subject { results }
          it { should be_empty }
        end
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
