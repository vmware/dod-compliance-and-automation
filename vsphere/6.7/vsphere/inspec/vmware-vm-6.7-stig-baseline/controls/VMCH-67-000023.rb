control "VMCH-67-000023" do
  title "3D features on the virtual machine must be disabled when not required."
  desc  "It is recommended that 3D acceleration be disabled on virtual machines
that do not require 3D functionality, (e.g. most server workloads or desktops
not using 3D applications)."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000023"
  tag stig_id: "VMCH-67-000023"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client select the Virtual Machine, right
click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration
Parameters >> Edit Configuration. Find the \"mks.enable3d\" value and verify it
is set to \"false\".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name mks.enable3d

If the virtual machine advanced setting \"mks.enable3d\" does not exist or is
not set to \"false\", this is a finding.

If a virtual machine requires 3D features, this is not a finding."
  desc 'fix', "From the vSphere Client select the Virtual Machine, right click and
go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters
>> Edit Configuration. Find the \"mks.enable3d\" value and set it to \"false\".

Note: The VM must be powered off to modify the advanced settings through the
vSphere Web Client. It is recommended to configure these settings with PowerCLI
as this can be done while the VM is powered on. In this case the modified
settings will not take effect until a cold boot of the VM.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

If the setting does not exist, run:

Get-VM \"VM Name\" | New-AdvancedSetting -Name mks.enable3d -Value false

If the setting exists, run:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name mks.enable3d |
Set-AdvancedSetting -Value false"

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name mks.enable3d).value"
  describe powercli_command(command).stdout.strip do
    it { should cmp "false" }
  end

end

