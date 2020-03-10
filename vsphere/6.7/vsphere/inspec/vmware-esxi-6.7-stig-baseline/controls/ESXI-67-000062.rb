control "ESXI-67-000062" do
  title "The ESXi host must prevent unintended use of the dvFilter network
APIs."
  desc  "If you are not using products that make use of the dvfilter network
API, the host should not be configured to send network information to a VM. If
the API is enabled an attacker might attempt to connect a VM to it thereby
potentially providing access to the network of other VMs on the host. If you
are using a product that makes use of this API then verify that the host has
been configured correctly. If you are not using such a product make sure the
setting is blank."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000062"
  tag stig_id: "ESXI-67-000062"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the Net.DVFilterBindIpAddress
value and verify the value is blank or the correct IP address of a security
appliance if in use.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress

If the Net.DVFilterBindIpAddress is not blank and security appliances are not
in use on the host, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
Net.DVFilterBindIpAddress value and remove any incorrect addresses.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress |
Set-AdvancedSetting -Value \"\""

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "" }
  end

end

