control "ESXI-67-000001" do
  title "Access to the ESXi host must be limited by enabling Lockdown Mode."
  desc  "Enabling lockdown mode disables direct access to an ESXi host
requiring the host be managed remotely from vCenter Server. This is done to
ensure the roles and access controls implemented in vCenter are always enforced
and users cannot bypass them by logging into a host directly. By forcing all
interaction to occur through vCenter Server, the risk of someone inadvertently
attaining elevated privileges or performing tasks that are not properly audited
is greatly reduced."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000027-VMM-000080"
  tag rid: "ESXI-67-000001"
  tag stig_id: "ESXI-67-000001"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Security Profile.  Scroll down to \"Lockdown Mode\" and verify it
is set to Enabled (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Select
Name,@{N=\"Lockdown\";E={$_.Extensiondata.Config.LockdownMode}}

If Lockdown Mode is disabled, this is a finding.

For environments that do not use vCenter server to manage ESXi, this is not
applicable."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Security Profile. Click edit on \"Lockdown Mode\" and set to Enabled
(Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

$level = \"lockdownNormal\" OR \"lockdownStrict\"
$vmhost = Get-VMHost -Name <hostname> | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.ChangeLockdownMode($level)

Note: In strict lockdown mode the DCUI service is stopped. If the connection to
vCenter Server is lost and the vSphere Client is no longer available, the ESXi
host becomes inaccessible."

  command = "(Get-VMHost -Name #{input('vmhostName')}).Extensiondata.Config.LockdownMode"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match "lockdownDisabled" }
  end

end

