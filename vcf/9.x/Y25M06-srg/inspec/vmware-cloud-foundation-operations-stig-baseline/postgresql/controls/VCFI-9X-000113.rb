control 'VCFI-9X-000113' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must log all client disconnections.'
  desc  "
    Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

    For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to PostgreSQL lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW log_disconnections;'\"

    Example result:

    on

    If the \"log_disconnections\" setting is not configured to \"on\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET log_disconnections TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-VCFI-9X-000113'
  tag rid: 'SV-VCFI-9X-000113'
  tag stig_id: 'VCFI-9X-000113'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW log_disconnections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
