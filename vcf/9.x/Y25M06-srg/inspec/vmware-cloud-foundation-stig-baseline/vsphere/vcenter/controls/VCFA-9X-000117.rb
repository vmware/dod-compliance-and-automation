control 'VCFA-9X-000117' do
  title 'The VMware Cloud Foundation vCenter Server must notify system administrators (SAs) and the information system security officer (ISSO) when Single Sign-On (SSO) account actions occur.'
  desc  "
    Once an attacker establishes initial access to a system, they often attempt to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. They may also try to hijack an existing account by changing a password or enabling a previously disabled account. Therefore, all actions performed on accounts in the SSO domain must be alerted on in vCenter at a minimum and ideally on a Security Information and Event Management (SIEM) system as well.

    To ensure the appropriate personnel are alerted about SSO account actions, create a new vCenter alarm for the \"com.vmware.sso.PrincipalManagement\" event ID and configure the alert mechanisms appropriately.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Alarm Definitions.

    Verify there is an alarm created to alert upon all SSO account actions. The alarm should trigger a warning on \"Principal Management event in SSO\" or \"com.vmware.sso.PrincipalManagement\" events.

    The alarm name may vary, but it is suggested to name it \"SSO Account Action Alert\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq \"com.vmware.sso.PrincipalManagement\"} | Select Name,Enabled,@{N=\"EventTypeId\";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

    If an alarm is not created and enabled to alert on SSO account actions, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select a vCenter Server >> Configure >> Alarm Definitions.

    Click \"Add\".

    Provide the alarm name of \"SSO Account Action Alert\" and an optional description.

    From the \"Target type\" dropdown menu, select \"vCenter Server\".

    Click \"Next\".

    In the \"Select a trigger\" field type \"SSO\" and select \"Principal Management event in SSO\" from the search results.

    Next to \"Trigger the alarm and\", select \"Show as Warning\".

    Configure the desired notification actions that will inform the SA and ISSO of the event.

    Click \"Next\". Click \"Next\" again. Click \"Create\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $entity = New-Object VMware.Vim.ManagedObjectReference
    $entity.Type = 'Folder'
    $entity.Value = 'group-d1'
    $spec = New-Object VMware.Vim.AlarmSpec
    $spec.Expression = New-Object VMware.Vim.OrAlarmExpression
    $spec.Expression.Expression = New-Object VMware.Vim.AlarmExpression[] (1)
    $spec.Expression.Expression[0] = New-Object VMware.Vim.EventAlarmExpression
    $spec.Expression.Expression[0].EventTypeId = 'com.vmware.sso.PrincipalManagement'
    $spec.Expression.Expression[0].EventType = \"Event\"
    $spec.Expression.Expression[0].ObjectType = \"Folder\"
    $spec.Expression.Expression[0].Status = 'yellow'
    $spec.Name = 'SSO Account Action Alert'
    $spec.Description = 'Alert on any SSO account action and show warning in vCenter.'
    $spec.Enabled = $true
    $spec.Setting = New-Object VMware.Vim.AlarmSetting
    $spec.Setting.ToleranceRange = 0
    $spec.Setting.ReportingFrequency = 300
    $amview = Get-View -Id 'AlarmManager-AlarmManager'
    $amview.CreateAlarm($entity, $spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000291'
  tag satisfies: ['SRG-APP-000292', 'SRG-APP-000293', 'SRG-APP-000294']
  tag gid: 'V-VCFA-9X-000117'
  tag rid: 'SV-VCFA-9X-000117'
  tag stig_id: 'VCFA-9X-000117'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  command = 'Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"} | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe 'An alarm for event ID com.vmware.sso.PrincipalManagement' do
      subject { result }
      it { should_not be_blank }
    end
  else
    resultjson = json(content: result)
    describe "Alarm for event ID com.vmware.sso.PrincipalManagement with Name: #{resultjson['Name']}" do
      subject { resultjson }
      its(['Enabled']) { should cmp true }
    end
  end
end
