control "ESXI-67-000060" do
  title "The virtual switch MAC Address Change policy must be set to reject on
the ESXi host."
  desc  "If the virtual machine operating system changes the MAC address, it
can send frames with an impersonated source MAC address at any time. This
allows it to stage malicious attacks on the devices in a network by
impersonating a network adaptor authorized by the receiving network. This will
prevent VMs from changing their effective MAC address. It will affect
applications that require this functionality. This will also affect how a layer
2 bridge will operate. This will also affect applications that require a
specific MAC address for licensing. Reject MAC Changes can be set at the
vSwitch and/or the Portgroup level. You can override switch level settings at
the Portgroup level."
  impact 0.7
  tag severity: "CAT I"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000060"
  tag stig_id: "ESXI-67-000060"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client go to Configure >> Networking >> Virtual
Switches. View the properties on each virtual switch and port group and verify
\"MAC Address Changes\" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the \"MAC Address Changes\" policy is set to accept (or true, via PowerCLI),
this is a finding."
  desc 'fix', "From the vSphere Client go to Configure >> Networking >> Virtual
Switches. For each virtual switch and port group click Edit settings (dots) and
change \"MAC Address Changes\" to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy
-MacChangesInherited $true"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualSwitch | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match "True" }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object -ExpandProperty MacChanges"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match "True" }
  end

end

