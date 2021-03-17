# encoding: UTF-8

control 'ESXI-70-000059' do
  title "All port groups on standard switches must be configured to reject
forged transmits."
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
at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches
are addressed in the vCenter STIG. If there is no standard switch on the ESXi
host, this is not applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> Networking >> Virtual Switches. On each standard switch, click the
'...' button next to each port group. Click \"View Settings\". Click the
\"Policies\" tab. Verify that \"Forged transmits\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VirtualSwitch | Get-SecurityPolicy
    Get-VirtualPortGroup | Get-SecurityPolicy

    If the \"Forged Transmits\" policy is set to \"Accept\" (or true, via
PowerCLI), this is a finding.
  "
  desc  'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> Networking >> Virtual Switches. On each standard switch, click the
'...' button next to each port group. Click \"Edit Settings\". Click the
\"Security\" tab. Set \"Forged transmits\" to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy
-ForgedTransmits $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy
-ForgedTransmitsInherited $true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000059'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualSwitch | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
  describe powercli_command(command) do
    its ('stdout.strip') { should_not match "True" }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object -ExpandProperty ForgedTransmits"
  describe powercli_command(command) do
    its ('stdout.strip') { should_not match "True" }
  end

end

