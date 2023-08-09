control 'VMCH-70-000029' do
  title 'Encryption must be enabled for Fault Tolerance on the virtual machine (VM).'
  desc %q(Fault Tolerance log traffic can be encrypted. This could contain sensitive data from the protected machine's memory or CPU instructions.

vSphere Fault Tolerance performs frequent checks between a primary VM and secondary VM so the secondary VM can quickly resume from the last successful checkpoint. The checkpoint contains the VM state that has been modified since the previous checkpoint.

When Fault Tolerance is turned on, FT encryption is set to "Opportunistic" by default, which means it enables encryption only if both the primary and secondary host are capable of encryption.)
  desc 'check', 'If the VM does not have Fault Tolerance enabled, this is not applicable.

From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Encryption >> Encrypted FT.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Where {($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionOpportunistic") -and ($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionRequired")}

If the setting does not have a value of "Opportunistic" or "Required", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Encryption >> FT Encryption.

Set the value to "Opportunistic" or "Required".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$spec.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
$spec.FT = ftEncryptionOpportunistic or ftEncryptionRequired
(Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)'
  impact 0.5
  tag check_id: 'C-60152r886472_chk'
  tag severity: 'medium'
  tag gid: 'V-256477'
  tag rid: 'SV-256477r886474_rule'
  tag stig_id: 'VMCH-70-000029'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60095r886473_fix'
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
    list = ['ftEncryptionOpportunistic', 'ftEncryptionRequired']
    vms.each do |vm|
      command = "(Get-VM -Name '#{vm}').ExtensionData.Config.FtEncryptionMode"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
