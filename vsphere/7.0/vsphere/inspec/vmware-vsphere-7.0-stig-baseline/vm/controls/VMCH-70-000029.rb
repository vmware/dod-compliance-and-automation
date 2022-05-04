control 'VMCH-70-000029' do
  title 'Encryption must be enabled for Fault Tolerance on the virtual machine.'
  desc  "
    You can encrypt Fault Tolerance log traffic which could contain sensitive data from the protected machines memory or cpu instructions.

    vSphere Fault Tolerance performs frequent checks between a primary VM and secondary VM so that the secondary VM can quickly resume from the last successful checkpoint. The checkpoint contains the VM state that has been modified since the previous checkpoint.

    When you turn on Fault Tolerance, FT encryption is set to \"Opportunistic\" by default, which means it enables encryption only if both the primary and secondary host are capable of encryption.
  "
  desc  'rationale', ''
  desc  'check', "
    If the Virtual Machine does not have Fault Tolerance enabled, this is Not Applicable.

    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Encryption >> Encrypted FT.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {($_.ExtensionData.Config.FtEncryptionMode -ne \"ftEncryptionOpportunistic\") -and ($_.ExtensionData.Config.FtEncryptionMode -ne \"ftEncryptionRequired\")}

    If the setting does not have a value of \"Opportunistic\" or \"Required\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Encryption >> FT Encryption.

    Set the value to \"Opportunistic\" or \"Required\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command(s):

    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
    $spec.FT = ftEncryptionOpportunistic or ftEncryptionRequired
    (Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000029'
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
    list = ['ftEncryptionOpportunistic', 'ftEncryptionRequired']
    vms.each do |vm|
      command = "(Get-VM -Name #{vm}).ExtensionData.Config.FtEncryptionMode"
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
