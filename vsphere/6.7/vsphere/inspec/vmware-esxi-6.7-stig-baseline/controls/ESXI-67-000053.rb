control "ESXI-67-000053" do
  title "SNMP must be configured properly on the ESXi host."
  desc  "If SNMP is not being used, it must remain disabled. If it is being
used, the proper trap destination must be configured. If SNMP is not properly
configured, monitoring information can be sent to a malicious host that can
then use this information to plan an attack."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000053"
  tag stig_id: "ESXI-67-000053"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From a PowerCLI command prompt while connected to the ESXi host
run the following command:

Get-VMHostSnmp | Select *

or

From an console or ssh session run the follow command:

esxcli system snmp get

If SNMP is not in use and is enabled, this is a finding.

If SNMP is enabled and read only communities is set to public, this is a
finding.

If SNMP is enabled and is not using v3 targets, this is a finding.

Note: SNMP v3 targets can only be viewed and configured from the esxcli
command."
  desc 'fix', "To disable SNMP run the following command from a PowerCLI command
prompt while connected to the ESXi Host:

Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false

or

From a console or ssh session run the follow command:

esxcli system snmp set -e no

To configure SNMP for v3 targets use the \"esxcli system snmp set\" command
set."

#Need to add logic if snmp is enabled to check for v3

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.snmp.get.Invoke() | Select-Object -ExpandProperty enable"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "false" }
  end

end

