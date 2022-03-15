control 'ESXI-67-000034' do
  title 'The ESXi host must disable the Managed Object Browser (MOB).'
  desc  "The MOB provides a way to explore the object model used by the
VMkernel to manage the host and enables configurations to be changed as well.
This interface is meant to be used primarily for debugging the vSphere SDK, but
because there are no access controls it could also be used as a method to
obtain information about a host being targeted for unauthorized access."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi Host and go to Configure >> System
>> Advanced System Settings.

    Select the \"Config.HostAgent.plugins.solo.enableMob\" value and verify it
is set to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.solo.enableMob

    If the \"Config.HostAgent.plugins.solo.enableMob\" setting is not set to
\"false\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi Host and go to Configure >> System
>> Advanced System Settings.

    Click \"Edit\" and select the \"Config.HostAgent.plugins.solo.enableMob\"
value and configure it to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag gid: 'V-239289'
  tag rid: 'SV-239289r674796_rule'
  tag stig_id: 'ESXI-67-000034'
  tag fix_id: 'F-42481r674795_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'false' }
  end
end
