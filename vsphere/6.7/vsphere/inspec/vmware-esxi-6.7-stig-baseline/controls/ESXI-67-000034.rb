control "ESXI-67-000034" do
  title "The ESXi host must disable the Managed Object Browser (MOB)."
  desc  "The Managed Object Browser (MOB) provides a way to explore the object
model used by the VMkernel to manage the host and enables configurations to be
changed as well. This interface is meant to be used primarily for debugging the
vSphere SDK, but because there are no access controls it could also be used as
a method obtain information about a host being targeted for unauthorized
access."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000095-VMM-000480"
  tag rid: "ESXI-67-000034"
  tag stig_id: "ESXI-67-000034"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the
Config.HostAgent.plugins.solo.enableMob value and verify it is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

If the Config.HostAgent.plugins.solo.enableMob setting is not set to false,
this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
Config.HostAgent.plugins.solo.enableMob value and configure it to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob
| Set-AdvancedSetting -Value false"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "false" }
  end

end

