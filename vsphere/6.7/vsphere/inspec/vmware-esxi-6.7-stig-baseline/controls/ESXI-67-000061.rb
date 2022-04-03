control 'ESXI-67-000061' do
  title "The virtual switch Promiscuous Mode policy must be set to reject on
the ESXi host."
  desc  "When Promiscuous Mode is enabled for a virtual switch, all virtual
machines connected to the Portgroup have the potential of reading all packets
across that network, meaning only the virtual machines connected to that
Portgroup.

    Promiscuous Mode is disabled by default on the ESXi Server, and this is the
recommended setting. Promiscuous Mode can be set at the vSwitch and/or the
Portgroup level. Switch-level settings can be overridden at the Portgroup level.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Configure >> Networking >> Virtual Switches.

    View the properties on each virtual switch and port group and verify that
\"Promiscuous Mode\" is set to reject.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VirtualSwitch | Get-SecurityPolicy
    Get-VirtualPortGroup | Get-SecurityPolicy

    If the \"Promiscuous Mode\" policy is set to accept (or true, via
PowerCLI), this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Configure >> Networking >> Virtual Switches.

    For each virtual switch and port group, click Edit settings (dots) and
change \"Promiscuous Mode\" to reject.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy
-AllowPromiscuous $false
    Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy
-AllowPromiscuousInherited $true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239315'
  tag rid: 'SV-239315r674874_rule'
  tag stig_id: 'ESXI-67-000061'
  tag fix_id: 'F-42507r674873_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualSwitch | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match 'True' }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match 'True' }
  end
end
