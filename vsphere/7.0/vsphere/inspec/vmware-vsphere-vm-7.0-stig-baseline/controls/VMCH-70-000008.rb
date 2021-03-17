# encoding: UTF-8

control 'VMCH-70-000008' do
  title "Unauthorized floppy devices must be disconnected on the virtual
machine."
  desc  "Ensure that no device is connected to a virtual machine if it is not
required. For example, floppy, serial and parallel ports are rarely used for
virtual machines in a datacenter environment, and CD/DVD drives are usually
connected only temporarily during software installation."
  desc  'rationale', ''
  desc  'check', "
    Floppy drives are no longer visible through the vSphere Client and must be
done via the API or PowerCLI.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

    If a virtual machine has a floppy drive connected, this is a finding.
  "
  desc  'fix', "
    Floppy drives are no longer visible through the vSphere Client and must be
done via the API or PowerCLI.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM \"VM Name\" | Get-FloppyDrive | Remove-FloppyDrive

    Note - The VM must be powered off to remove the floppy drive.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000008'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "Get-VM -Name #{input('vmName')} | Get-FloppyDrive"
  describe powercli_command(command) do
    its ('stdout') { should be_empty }
    its ('exit_status') { should cmp 0 }
  end

end

