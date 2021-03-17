# encoding: UTF-8

control 'VCSA-70-000008' do
  title "The vCenter Server must provide an immediate real-time alert to the SA
and ISSO, at a minimum, if the syslog server becomes unreachable."
  desc  "It is critical for the appropriate personnel to be aware if an ESXi
host is at risk of failing to process audit logs as required. Without a
real-time alert, security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    To ensure the appropriate personnel are alerted if an audit failure occurs
a vCenter alarm can be created to trigger when an ESXi host can no longer reach
its syslog server.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server
>> Configure >> Security >> Alarm Definitions. Verify there is an alarm created
to alert if an ESXi host can no longer reach its syslog server.  The alarm
definition will have a rule for the \"Remote logging host has become
unreachable.\" event.

    or

    From a PowerCLI command prompt while connected to the vCenter server run
the following command:

    Get-AlarmDefinition | Where
{$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq
\"esx.problem.vmsyslogd.remote.failure\"} | Select
Name,Enabled,@{N=\"EventTypeId\";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

    If an alarm is not created to alert when syslog failures occur and enabled,
this is a finding.
  "
  desc  'fix', "
    From the vSphere Client, go to Host and Clusters >> Select a vCenter Server
>> Configure >> Security >> Alarm Definitions. Click \"Add\". Provide an alarm
name and description. From the 'Target type' dropdown menu, select \"Hosts\".
Click \"Next\".

    Paste \"esx.problem.vmsyslogd.remote.failure\" (without quotes) in the line
after \"IF\" and hit enter. Next to \"Trigger the alarm and\" select \"Show as
Warning\". Configure the desired notification actions. Click Next. Click Next.
Click Create.

    Note - This alarm will only trigger if syslog is configured for TCP or SSL
connections. UDP is stateless and the host cannot determine if UDP packets
reached the central log server.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000108'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000008'
  tag fix_id: nil
  tag cci: 'CCI-000139'
  tag nist: ['AU-5 a']

  command = "Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq \"esx.problem.vmsyslogd.remote.failure\"} | Select-Object -ExpandProperty Enabled"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "true" }
  end

end

