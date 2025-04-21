control 'VMCH-70-000007' do
  title 'Host Guest File System (HGFS) file transfers must be disabled on the virtual machine (VM).'
  desc %q(Setting "isolation.tools.hgfsServerSet.disable" to "true" disables registration of the guest's HGFS server with the host. Application Programming Interfaces (APIs) that use HGFS to transfer files to and from the guest operating system, such as some VIX commands, will not function. An attacker could use this to transfer files inside the guest operating system.)
  desc 'check', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Verify the "isolation.tools.hgfsServerSet.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable

If the virtual machine advanced setting "isolation.tools.hgfsServerSet.disable" does not exist or is not set to "true", this is a finding.'
  desc 'fix', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "isolation.tools.hgfsServerSet.disable" value and set it to "true".

If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as shown below.

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable | Set-AdvancedSetting -Value true'
  impact 0.5
  tag check_id: 'C-60131r886409_chk'
  tag severity: 'medium'
  tag gid: 'V-256456'
  tag rid: 'SV-256456r886411_rule'
  tag stig_id: 'VMCH-70-000007'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60074r886410_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
