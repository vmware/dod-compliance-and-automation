control 'VCSA-70-000123' do
  title 'The vCenter Server must provide an immediate real-time alert to the SA and ISSO, at a minimum, on every SSO account action.'
  desc  "
    Once an attacker establishes initial access to a system, they often attempt to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. They may also try to hijack an existing account by changing a password or by enabling a previously disabled account. As such, all actions performed on accounts in the SSO domain much be alerted on in vCenter at a minimum and ideally on a SIEM as well.

    To ensure the appropriate personnel are alerted about SSO account actions, create a new vCenter alarm for the \"com.vmware.sso.PrincipalManagement\" event ID and configure the alert mechanisms appropriately.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Security >> Alarm Definitions.

    Verify there is an alarm created to alert upon all SSO account actions.

    The alarm name may vary but it is suggested to name it \"SSO account actions - com.vmware.sso.PrincipalManagement\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq \"com.vmware.sso.PrincipalManagement\"} | Select Name,Enabled,@{N=\"EventTypeId\";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

    If an alarm is not created to alert on SSO account actions, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server >> Configure >> Security >> Alarm Definitions.

    Click \"Add\".

    Provide the alarm name of \"SSO account actions - com.vmware.sso.PrincipalManagement\" and an optional description.

    From the \"Target type\" dropdown menu, select \"vCenter Server\".

    Click \"Next\".

    Paste \"com.vmware.sso.PrincipalManagement\" (without quotes) in the line after \"IF\" and hit enter.

    Next to \"Trigger the alarm and\" select \"Show as Warning\".

    Configure the desired notification actions that will inform the SA and ISSO of the event.

    Click \"Next\". Click \"Next\". Click \"Create\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000291'
  tag satisfies: ['SRG-APP-000292', 'SRG-APP-000293', 'SRG-APP-000294', 'SRG-APP-000320']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000123'
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-002132']
  tag nist: ['AC-2 (4)']

  command = 'Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"} | Select-Object -ExpandProperty Enabled'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
