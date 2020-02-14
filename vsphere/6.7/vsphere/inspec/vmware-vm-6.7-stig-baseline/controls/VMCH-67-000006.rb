control "VMCH-67-000006" do
  title "Independent, non-persistent disks must be not be used on the virtual
machine."
  desc  "The security issue with nonpersistent disk mode is that successful
attackers, with a simple shutdown or reboot, might undo or remove any traces
that they were ever on the machine. To safeguard against this risk, production
virtual machines should be set to use persistent disk mode; additionally, make
sure that activity within the VM is logged remotely on a separate server, such
as a syslog server or equivalent Windows-based event collector. Without a
persistent record of activity on a VM, administrators might never know whether
they have been attacked or hacked.

    There can be valid use cases for these types of disks such as with an
application presentation solution where read only disks are desired and such
cases should be identified and documented."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000006"
  tag stig_id: "VMCH-67-000006"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client right-click the Virtual Machine and
go to Edit Settings. Review the attached hard disks and verify they are not
configured as independent nonpersistent disks.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-HardDisk | Select Parent, Name, Filename, DiskType,
Persistence | FT -AutoSize

If the virtual machine has attached disks that are in independent nonpersistent
mode and are not documented, this is a finding."
  desc 'fix', "From the vSphere Web Client right-click the Virtual Machine and go
to Edit Settings. Select the target hard disk and change the mode to persistent
or uncheck Independent.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-HardDisk | Set-HardDisk -Persistence
IndependentPersistent

or

Get-VM \"VM Name\" | Get-HardDisk | Set-HardDisk -Persistence Persistent"

  command = "(Get-VM -Name #{input('vmName')} | Get-HardDisk).Persistence"
  results = powercli_command(command)
  results.stdout.split.each do | disk |
    describe "Checking the VM for Non-Persistent Hard Disks" do
      subject {disk}
      it {should_not cmp "IndependentNonPersistent"}
    end
  end

end

