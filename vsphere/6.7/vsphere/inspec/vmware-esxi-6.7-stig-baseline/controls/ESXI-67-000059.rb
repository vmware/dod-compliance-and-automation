control "ESXI-67-000059" do
  title "The virtual switch Forged Transmits policy must be set to reject on
the ESXi host."
  desc  "If the virtual machine operating system changes the MAC address, the
operating system can send frames with an impersonated source MAC address at any
time. This allows an operating system to stage malicious attacks on the devices
in a network by impersonating a network adaptor authorized by the receiving
network.

    This means the virtual switch does not compare the source and effective MAC
addresses.

    To protect against MAC address impersonation, all virtual switches should
have forged transmissions set to Reject. Reject Forged Transmit can be set at
the vSwitch and/or the Portgroup level. You can override switch level settings
at the Portgroup level."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000059"
  tag stig_id: "ESXI-67-000059"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client go to Configure >> Networking >> Virtual
Switches. View the properties on each virtual switch and port group and verify
\"Forged Transmits\" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the \"Forged Transmits\" policy is set to accept (or true, via PowerCLI),
this is a finding."
  desc 'fix', "From the vSphere Client go to Configure >> Networking >> Virtual
Switches. For each virtual switch and port group click Edit settings (dots) and
change \"Forged Transmits\" to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits
$false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy
-ForgedTransmitsInherited $true"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualSwitch | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match "True" }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match "True" }
  end

end

