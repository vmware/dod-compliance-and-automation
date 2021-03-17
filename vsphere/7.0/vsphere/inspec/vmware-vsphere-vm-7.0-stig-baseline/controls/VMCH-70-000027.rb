# encoding: UTF-8

control 'VMCH-70-000027' do
  title 'Log retention must be properly configured on the virtual machine.'
  desc  "The ESXi hypervisor maintains logs for each individual VM by default.
These logs contain information including, but not limited to, power events,
system failure information, tools status and activity, time sync, virtual
hardware changes, vMotion migrations and machine clones. By default, ten of
these logs are retained. This is normally sufficient for most environments but
this configuration must be verified and maintained."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the \"vmx.log.keepOld\" value and verify it is set to
\"10\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name vmx.log.keepOld

    If the virtual machine advanced setting \"vmx.log.keepOld\" is not set to
\"10\", this is a finding.

    If the virtual machine advanced setting \"vmx.log.keepOld\" does not exist,
this is not a finding.
  "
  desc  'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to
Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the \"vmx.log.keepOld\" value and set it to \"10\".

    Note: The VM must be powered off to modify the advanced settings through
the vSphere Client. It is recommended to configure these settings with PowerCLI
as this can be done while the VM is powered on. In this case the modified
settings will not take effect until a cold boot of the VM.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name vmx.log.keepOld -Value 10

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name vmx.log.keepOld |
Set-AdvancedSetting -Value 10
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000027'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name vmx.log.keepOld).value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "10" }
    its ('exit_status') { should cmp 0 }
  end

end

