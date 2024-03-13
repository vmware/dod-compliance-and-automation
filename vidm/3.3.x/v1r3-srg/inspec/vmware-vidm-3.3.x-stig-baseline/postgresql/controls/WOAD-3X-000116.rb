control 'WOAD-3X-000116' do
  title 'The Workspace ONE Access vPostgres instance must log all connection attempts.'
  desc  "For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to VMware Postgres. Setting 'log_connections' to 'on' will cause each attempted connection to the server to be logged, as well as successful completion of client authentication."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_connections\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_connections TO 'on';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag satisfies: ['SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353']
  tag gid: 'V-WOAD-3X-000116'
  tag rid: 'SV-WOAD-3X-000116'
  tag stig_id: 'WOAD-3X-000116'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_connections;"') do
      its('stdout.strip') { should cmp 'on' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_connections;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'on' }
    end
  end
end
