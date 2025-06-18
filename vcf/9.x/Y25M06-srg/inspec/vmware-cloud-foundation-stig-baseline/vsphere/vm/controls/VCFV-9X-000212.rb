control 'VCFV-9X-000212' do
  title 'Virtual machines (VMs) must enable logging.'
  desc  'The ESX hypervisor maintains logs for each individual VM by default. These logs contain information including, but not limited to, power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones. Due to the value these logs provide for the continued availability of each VM and potential security incidents, these logs must be enabled.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced.

    Ensure that the checkbox next to \"Enable logging\" is checked.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Flags.EnableLogging -ne \"True\"}

    If logging is not enabled, this is a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced.

    Click the checkbox next to \"Enable logging\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following commands:

    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
    $spec.Flags.enableLogging = $true
    (Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000212'
  tag rid: 'SV-VCFV-9X-000212'
  tag stig_id: 'VCFV-9X-000212'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []

  unless vmName.blank?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless vmcluster.blank?
    vms = powercli_command("Get-VM -Location (Get-Cluster -Name '#{vmcluster}') | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vms.blank?
    describe 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vms.each do |vm|
      command = "(Get-VM -Name '#{vm}').ExtensionData.Config.Flags | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      describe "Logging on VM: #{vm}" do
        subject { json(content: result) }
        its(['EnableLogging']) { should cmp 'true' }
      end
    end
  end
end
