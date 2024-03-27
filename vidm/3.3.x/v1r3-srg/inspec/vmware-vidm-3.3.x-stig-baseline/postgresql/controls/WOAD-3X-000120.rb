control 'WOAD-3X-000120' do
  title 'The Workspace ONE Access vPostgres instance must log all client disconnections.'
  desc  "
    Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

    For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to VMware Postgres lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    #/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_disconnections\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_disconnections TO 'on';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-WOAD-3X-000120'
  tag rid: 'SV-WOAD-3X-000120'
  tag stig_id: 'WOAD-3X-000120'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_disconnections;"') do
      its('stdout.strip') { should cmp 'on' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_disconnections;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'on' }
    end
  end
end
