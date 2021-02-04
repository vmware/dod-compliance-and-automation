control "ESXI-67-000003" do
  title "The ESXi host must verify the exception users list for lockdown mode."
  desc  "In vSphere you can add users to the Exception Users list from the
vSphere Web Client. These users do not lose their permissions when the host
enters lockdown mode. Usually you may want to add service accounts such as a
backup agent to the Exception Users list. Verify that the list of users who are
exempted from losing permissions is legitimate and as needed per your
environment. Users who do not require special permissions should not be
exempted from lockdown mode."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000003"
  tag stig_id: "ESXI-67-000003"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Security Profile.  Under Lockdown Mode, review the Exception Users
list.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following script:

$vmhost = Get-VMHost | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

If the Exception Users list contains accounts that do not require special
permissions, this is a finding.

Note - This list is not intended for system administrator accounts but for
special circumstances such as a service account.

For environments that do not use vCenter server to manage ESXi, this is not
applicable."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Security Profile.  Under Lockdown Mode, click Edit and remove
unnecessary users from the exceptions list."

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')} | Get-View; (Get-View $vmhost.ConfigManager.HostAccessManager).QueryLockdownExceptions()"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "#{input('exceptionUsers')}" }
  end

end

