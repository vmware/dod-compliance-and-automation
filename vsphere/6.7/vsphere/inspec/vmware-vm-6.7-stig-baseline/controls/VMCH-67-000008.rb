control "VMCH-67-000008" do
  title "Unauthorized floppy devices must be disconnected on the virtual
machine."
  desc  "Ensure that no device is connected to a virtual machine if it is not
required. For example, floppy, serial and parallel ports are rarely used for
virtual machines in a datacenter environment, and CD/DVD drives are usually
connected only temporarily during software installation."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000008"
  tag stig_id: "VMCH-67-000008"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client right-click the Virtual Machine and
go to Edit Settings. Review the VMs hardware and verify no floppy device is
connected.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

If a virtual machine has a floppy drive connected, this is a finding."
  desc 'fix', "If the floppy drive is required to be present, then from the
vSphere Client right-click the Virtual Machine and go to Edit Settings, make
sure the drive is not connected and will not \"Connect at power on\".

If the floppy drive is not required, then from the vSphere Client power off the
virtual machine, right-click the Virtual Machine and go to Edit Settings,
select the floppy drive and click the circle-x to remove then OK.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-FloppyDrive | Remove-FloppyDrive"

  command = "Get-VM -Name #{input('vmName')} | Get-FloppyDrive"
  describe powercli_command(command).stdout do
    it { should be_empty }
  end

end

