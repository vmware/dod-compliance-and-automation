control 'CFPG-4X-000005' do
  title 'The SDDC Manager PostgreSQL service must produce logs containing sufficient information to establish what type of events occurred.'
  desc  "
    Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.

    Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_line_prefix\"

    Expected result:

    %m %c %x %d %u %r %p %l

    If the output does not include the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_line_prefix = '%m %c %x %d %u %r %p %l';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag gid: 'V-CFPG-4X-000005'
  tag rid: 'SV-CFPG-4X-000005'
  tag stig_id: 'CFPG-4X-000005'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_line_prefix;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_line_prefix')}" }
  end
end
