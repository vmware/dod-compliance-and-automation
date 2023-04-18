control 'VMCH-80-000203' do
  title 'Virtual machines (VMs) must enable encryption for vMotion.'
  desc  "
    vMotion migrations in vSphere 6.0 and earlier transferred working memory and CPU state information in clear text over the vMotion network. As of vSphere 6.5, this transfer can be transparently encrypted using 256-bit AES-GCM with negligible performance impact.

    vSphere enables encrypted vMotion by default as \"Opportunistic\", meaning that encrypted channels are used where supported, but the operation will continue in plain text where encryption is not supported.

    For example, when vMotioning between two hosts, encryption will always be used. However, because 6.0 and earlier releases do not support this feature, vMotion from a 7.0 host to a 6.0 host would be allowed but would not be encrypted. If the encryption is set to \"Required\", vMotions to unsupported hosts will fail. This must be set to \"Opportunistic\" or \"Required\".
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Encryption.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {($_.ExtensionData.Config.MigrateEncryption -eq \"disabled\")}

    If the \"Encrypted vMotion\" setting does not have a value of \"Opportunistic\" or \"Required\", this is a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Encryption.

    For \"Encrypted vMotion\" set the value to \"Opportunistic\" or \"Required\". Click \"OK\".

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
  tag gid: 'V-VMCH-80-000203'
  tag rid: 'SV-VMCH-80-000203'
  tag stig_id: 'VMCH-80-000203'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if !vms.empty?
    list = ['opportunistic', 'required']
    vms.each do |vm|
      command = "(Get-VM -Name '#{vm}').ExtensionData.Config.MigrateEncryption"
      result = powercli_command(command).stdout.strip
      describe "VM: #{vm}" do
        subject { result }
        it { should be_in list }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
