control 'VMCH-70-000025' do
  title 'Logging must be enabled on the virtual machine.'
  desc  "The ESXi hypervisor maintains logs for each individual VM by default.
These logs contain information including, but not limited to, power events,
system failure information, tools status and activity, time sync, virtual
hardware changes, vMotion migrations and machine clones. Due to the value these
logs provide for the continued availability of each VM and potential security
incidents, these logs must be enabled."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Settings. Ensure that the
checkbox next to \"Enable logging\" is checked.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Flags.EnableLogging -ne \"True\"}

    If logging is not enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Settings. Click the checkbox
next to \"Enable logging\". Click \"OK\".

    or

  From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following commands:

$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$spec.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
$spec.Flags.enableLogging = $true
(Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000025'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "((Get-VM -Name #{input('vmName')}).ExtensionData.Config.Flags.EnableLogging)"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
    its('exit_status') { should cmp 0 }
  end
end
