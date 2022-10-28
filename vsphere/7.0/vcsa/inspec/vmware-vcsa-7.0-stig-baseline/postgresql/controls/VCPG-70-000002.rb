control 'VCPG-70-000002' do
  title 'VMware Postgres log files must contain required fields.'
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    As an embedded database that is only accessible via localhost, VMware Postgres on the VCSA does not implement robust auditing. However, it can and must be configured to log reasonable levels of information relating to user actions to enable proper troubleshooting.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW log_line_prefix;\"

    Expected result:

    %m %c %x %d %u %r %p %l

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET log_line_prefix TO '%m %c %x %d %u %r %p %l ';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag satisfies: ['SRG-APP-000095-DB-000039', 'SRG-APP-000096-DB-000040', 'SRG-APP-000097-DB-000041', 'SRG-APP-000098-DB-000042', 'SRG-APP-000099-DB-000043', 'SRG-APP-000100-DB-000201', 'SRG-APP-000101-DB-000044', 'SRG-APP-000375-DB-000323']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000002'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-001487', 'CCI-001889']
  tag nist: ['AU-12 a', 'AU-3', 'AU-3 (1)', 'AU-8 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_line_prefix;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_line_prefix')}" }
  end
end
