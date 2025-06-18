control 'VCFI-9X-000109' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must log all connection attempts.'
  desc  'For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to PostgreSQL. Setting "log_connections" to "on" will cause each attempted connection to the server to be logged, as well as successful completion of client authentication.'
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW log_connections;'\"

    Example result:

    on

    If the \"log_connections\" setting is not configured to \"on\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET log_connections TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag satisfies: ['SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353', 'SRG-APP-000508-DB-000358']
  tag gid: 'V-VCFI-9X-000109'
  tag rid: 'SV-VCFI-9X-000109'
  tag stig_id: 'VCFI-9X-000109'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW log_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
