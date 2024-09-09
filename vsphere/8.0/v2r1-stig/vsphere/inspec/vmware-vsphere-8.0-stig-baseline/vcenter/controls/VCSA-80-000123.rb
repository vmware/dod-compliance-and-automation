control 'VCSA-80-000123' do
  title 'The vCenter Server must provide an immediate real-time alert to the system administrator (SA) and information system security officer (ISSO), at a minimum, on every Single Sign-On (SSO) account action.'
  desc 'Once an attacker establishes initial access to a system, they often attempt to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. They may also try to hijack an existing account by changing a password or enabling a previously disabled account. Therefore, all actions performed on accounts in the SSO domain much be alerted on in vCenter at a minimum and ideally on a Security Information and Event Management (SIEM) system as well.

To ensure the appropriate personnel are alerted about SSO account actions, create a new vCenter alarm for the "com.vmware.sso.PrincipalManagement" event ID and configure the alert mechanisms appropriately.

'
  desc 'check', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Security >> Alarm Definitions.

Verify there is an alarm created to alert upon all SSO account actions.

The alarm name may vary, but it is suggested to name it "SSO account actions - com.vmware.sso.PrincipalManagement".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created to alert on SSO account actions, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vCenter Server >> Configure >> Security >> Alarm Definitions.

Click "Add".

Provide the alarm name of "SSO account actions - com.vmware.sso.PrincipalManagement" and an optional description.

From the "Target type" dropdown menu, select "vCenter Server".

Click "Next".

Paste "com.vmware.sso.PrincipalManagement" (without quotes) in the line after "IF" and press "Enter".

Next to "Trigger the alarm and", select "Show as Warning".

Configure the desired notification actions that will inform the SA and ISSO of the event.

Click "Next". Click "Next" again. Click "Create".'
  impact 0.5
  tag check_id: 'C-62663r934425_chk'
  tag severity: 'medium'
  tag gid: 'V-258923'
  tag rid: 'SV-258923r1003602_rule'
  tag stig_id: 'VCSA-80-000123'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-62572r934426_fix'
  tag satisfies: ['SRG-APP-000291', 'SRG-APP-000292', 'SRG-APP-000293', 'SRG-APP-000294', 'SRG-APP-000320']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  command = 'Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"} | Select-Object -ExpandProperty Enabled'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
