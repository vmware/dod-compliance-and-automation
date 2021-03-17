# encoding: UTF-8

control 'VMCH-70-000007' do
  title 'HGFS file transfers must be disabled on the virtual machine.'
  desc  "Setting isolation.tools.hgfsServerSet.disable to true disables
registration of the guest's HGFS server with the host. APIs that use HGFS to
transfer files to and from the guest operating system, such as some VIX
commands, will not function. An attacker could potentially use this to transfer
files inside the guest OS."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit
Configuration. Verify the isolation.tools.hgfsServerSet.disable value is set to
true.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name
isolation.tools.hgfsServerSet.disable

    If the virtual machine advanced setting
isolation.tools.hgfsServerSet.disable does not exist or is not set to true,
this is a finding.
  "
  desc  'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the isolation.tools.hgfsServerSet.disable value and set it
to true. If the setting does not exist, add the Name and Value setting at the
bottom of screen.

    Note: The VM must be powered off to configure the advanced settings through
the vSphere Client so it is recommended to configure these settings with
PowerCLI as it can be done while the VM is powered on. Settings do not take
effect via either method until the virtual machine is cold started, not
rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name
isolation.tools.hgfsServerSet.disable -Value true

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name
isolation.tools.hgfsServerSet.disable | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000007'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable).value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "true" }
    its ('exit_status') { should cmp 0 }
  end

end

