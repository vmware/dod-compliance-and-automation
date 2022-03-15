control 'VMCH-70-000026' do
  title 'Log size must be properly configured on the virtual machine.'
  desc  "The ESXi hypervisor maintains logs for each individual VM by default.
These logs contain information including, but not limited to, power events,
system failure information, tools status and activity, time sync, virtual
hardware changes, vMotion migrations and machine clones. By default, the size
of these logs is unlimited and they are only rotated on vMotion or power
events. This can cause storage issues at scale for VMs that do not vMotion or
power cycle often."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the \"vmx.log.rotateSize\" value and verify it is set to
\"2048000\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name vmx.log.rotateSize

    If the virtual machine advanced setting \"vmx.log.rotateSize\" does not
exist or is not set to \"2048000\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the \"vmx.log.rotateSize\" value and set it to \"2048000\".

    Note: The VM must be powered off to modify the advanced settings through
the vSphere Client. It is recommended to configure these settings with PowerCLI
as this can be done while the VM is powered on. In this case the modified
settings will not take effect until a cold boot of the VM.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name vmx.log.rotateSize -Value
2048000

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name vmx.log.rotateSize |
Set-AdvancedSetting -Value 2048000
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000026'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name vmx.log.rotateSize).value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '2048000' }
    its('exit_status') { should cmp 0 }
  end
end
