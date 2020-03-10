control "ESXI-67-000055" do
  title "The ESXi host must disable Inter-VM transparent page sharing."
  desc  "Published academic papers have demonstrated that by forcing a flush
and reload of cache memory, it is possible to measure memory timings to try and
determine an AES encryption key in use on another virtual machine running on
the same physical processor of the host server if Transparent Page Sharing is
enabled between the two virtual machines. This technique works only in a highly
controlled system configured in a non-standard way that VMware believes would
not be recreated in a production environment.

    Even though VMware believes information being disclosed in real world
conditions is unrealistic, out of an abundance of caution upcoming ESXi Update
releases will no longer enable TPS between Virtual Machines by default (TPS
will still be utilized within individual VMs)."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000055"
  tag stig_id: "ESXI-67-000055"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the Mem.ShareForceSalting value
and verify it is set to 2.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting

If the Mem.ShareForceSalting setting is not set to 2, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
Mem.ShareForceSalting value and configure it to 2.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting |
Set-AdvancedSetting -Value 2"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "2" }
  end

end

