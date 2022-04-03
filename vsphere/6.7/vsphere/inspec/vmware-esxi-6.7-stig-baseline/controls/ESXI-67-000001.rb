control 'ESXI-67-000001' do
  title 'Access to the ESXi host must be limited by enabling Lockdown Mode.'
  desc  "Enabling Lockdown Mode disables direct access to an ESXi host,
requiring the host to be managed remotely from vCenter Server. This is done to
ensure the roles and access controls implemented in vCenter are always enforced
and users cannot bypass them by logging on to a host directly. By forcing all
interaction to occur through vCenter Server, the risk of someone inadvertently
attaining elevated privileges or performing tasks that are not properly audited
is greatly reduced.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Security Profile.

    Scroll down to \"Lockdown Mode\" and verify it is enabled (\"Normal\" or
\"Strict\").

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Select
Name,@{N=\"Lockdown\";E={$_.Extensiondata.Config.LockdownMode}}

    If Lockdown Mode is disabled, this is a finding.

    For environments that do not use vCenter server to manage ESXi, this is Not
Applicable.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Security Profile.

    Click \"Edit\" in \"Lockdown Mode\" and enable (\"Normal\" or \"Strict\").

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    $level = \"lockdownNormal\" OR \"lockdownStrict\"
    $vmhost = Get-VMHost -Name <hostname> | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.ChangeLockdownMode($level)

    Note: In Strict Lockdown Mode, the DCUI service is stopped. If the
connection to vCenter Server is lost and the vSphere Client is no longer
available, the ESXi host becomes inaccessible.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag satisfies: ['SRG-OS-000027-VMM-000080', 'SRG-OS-000123-VMM-000620']
  tag gid: 'V-239258'
  tag rid: 'SV-239258r674703_rule'
  tag stig_id: 'ESXI-67-000001'
  tag fix_id: 'F-42450r674702_fix'
  tag cci: ['CCI-000054', 'CCI-001682']
  tag nist: ['AC-10', 'AC-2 (2)']

  list = ['Normal', 'Strict']
  command = "(Get-VMHost -Name #{input('vmhostName')}).Extensiondata.Config.LockdownMode"
  describe powercli_command(command) do
    its('stdout.strip') { should be_in list }
  end
end
