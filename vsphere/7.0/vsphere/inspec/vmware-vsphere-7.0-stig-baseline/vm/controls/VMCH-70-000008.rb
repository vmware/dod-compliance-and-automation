control 'VMCH-70-000008' do
  title 'Unauthorized floppy devices must be disconnected on the virtual machine (VM).'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    Floppy drives are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

    If a virtual machine has a floppy drive connected, this is a finding.
  "
  desc 'fix', "
    Floppy drives are no longer visible through the vSphere Client and must be done via the API or PowerCLI.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-FloppyDrive | Remove-FloppyDrive

    Note: The VM must be powered off to remove the floppy drive.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256457'
  tag rid: 'SV-256457r886414_rule'
  tag stig_id: 'VMCH-70-000008'
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
      command = "Get-VM -Name '#{vm}' | Get-FloppyDrive"
      describe powercli_command(command) do
        its('stdout.strip') { should be_empty }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
