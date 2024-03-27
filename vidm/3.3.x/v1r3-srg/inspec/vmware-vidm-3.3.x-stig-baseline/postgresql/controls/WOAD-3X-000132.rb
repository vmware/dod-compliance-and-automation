control 'WOAD-3X-000132' do
  title 'The Workspace ONE Access vPostgres instance must produce logs at the warning level at a minimum.'
  desc  "
    Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.

    Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_min_messages\"

    Expected result:

    warning

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_min_messages TO 'warning';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag gid: 'V-WOAD-3X-000132'
  tag rid: 'SV-WOAD-3X-000132'
  tag stig_id: 'WOAD-3X-000132'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3']

  levels = ['DEBUG5', 'DEBUG4', 'DEBUG3', 'DEBUG2', 'DEBUG1', 'INFO', 'NOTICE', 'WARNING', 'debug5', 'debug4', 'debug3', 'debug2', 'debug1', 'info', 'notice', 'warning']
  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_min_messages;"') do
      its('stdout.strip') { should be_in levels }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_min_messages;'

    describe sql.query(sqlquery) do
      its('output') { should be_in levels }
    end
  end
end
