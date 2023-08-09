control 'VMCH-70-000018' do
  title 'Shared salt values must be disabled on the virtual machine (VM).'
  desc %q(When salting is enabled (Mem.ShareForceSalting=1 or 2) to share a page between two virtual machines, both salt and the content of the page must be same. A salt value is a configurable advanced option for each virtual machine. The salt values can be specified manually in the virtual machine's advanced settings with the new option "sched.mem.pshare.salt".

If this option is not present in the virtual machine's advanced settings, the value of the "vc.uuid" option is taken as the default value. Because the "vc.uuid" is unique to each virtual machine, by default Transparent Page Sharing (TPS) happens only among the pages belonging to a particular virtual machine (Intra-VM).)
  desc 'check', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Verify the "sched.mem.pshare.salt" setting does not exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt

If the virtual machine advanced setting "sched.mem.pshare.salt" exists, this is a finding.'
  desc 'fix', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Delete the "sched.mem.pshare.salt" setting.

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting'
  impact 0.3
  tag check_id: 'C-60141r886439_chk'
  tag severity: 'low'
  tag gid: 'V-256466'
  tag rid: 'SV-256466r886441_rule'
  tag stig_id: 'VMCH-70-000018'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60084r886440_fix'
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
