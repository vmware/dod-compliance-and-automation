control 'VMCH-80-000199' do
  title 'Virtual machines (VMs) must have shared salt values disabled.'
  desc %q(When salting is enabled (Mem.ShareForceSalting=1 or 2) to share a page between two virtual machines, both salt and the content of the page must be same. A salt value is a configurable advanced option for each virtual machine. The salt values can be specified manually in the virtual machine's advanced settings with the new option "sched.mem.pshare.salt".

If this option is not present in the virtual machine's advanced settings, the value of the "vc.uuid" option is taken as the default value. Because the "vc.uuid" is unique to each virtual machine, by default Transparent Page Sharing (TPS) happens only among the pages belonging to a particular virtual machine (Intra-VM).)
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "sched.mem.pshare.salt" setting does not exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt

If the virtual machine advanced setting "sched.mem.pshare.salt" exists, this is a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Delete the "sched.mem.pshare.salt" setting.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.3
  tag check_id: 'C-62452r933195_chk'
  tag severity: 'low'
  tag gid: 'V-258712'
  tag rid: 'SV-258712r959010_rule'
  tag stig_id: 'VMCH-80-000199'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62361r933196_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name sched.mem.pshare.salt | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe "VM: #{vm}" do
        subject { result }
        it { should be_empty }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
