control 'VMCH-70-000024' do
  title 'Encryption must be enabled for vMotion on the virtual machine.'
  desc  "
    vMotion migrations in vSphere 6.0 and earlier transferred working memory and CPU state information in clear text over the vMotion network. As of vSphere 6.5 this transfer can be transparently encrypted using 256bit AES-GCM with negligible performance impact.

    vSphere enables encrypted vMotion by default as \"Opportunistic\", meaning that encrypted channels are used where supported but the operation will continue in plain text where encryption is not supported.

    For example when vMotioning between two hosts encryption will always be utilized but since 6.0 and earlier releases do not support this feature vMotion from a 7.0 host to a 6.0 host would be allowed but would not be encrypted. If this finding is set to \"Required\" then vMotions to unsupported hosts will fail. This setting must be set to \"Opportunistic\" or \"Required\".
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Encryption >> Encrypted vMotion.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {($_.ExtensionData.Config.MigrateEncryption -ne \"opportunistic\") -or ($_.ExtensionData.Config.MigrateEncryption -ne \"required\")}

    If the setting does not have a value of \"Opportunistic\" or \"Required\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Encryption >> Encrypted vMotion.

    Set the value to \"Opportunistic\" or \"Required\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.MigrateEncryption = New-Object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
    $spec.MigrateEncryption = $true
    (Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000024'
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
    list = ['opportunistic', 'required']
    vms.each do |vm|
      command = "(Get-VM -Name #{vm}).ExtensionData.Config.MigrateEncryption"
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
