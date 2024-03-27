control 'WOAD-3X-000130' do
  title 'The Workspace ONE Access vPostgres instance must be configured to generate logs to a standard destination.'
  desc  "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_destination\"

    Expected result:

    stderr

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_destination TO 'stderr';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-WOAD-3X-000130'
  tag rid: 'SV-WOAD-3X-000130'
  tag stig_id: 'WOAD-3X-000130'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_destination;"') do
      its('stdout.strip') { should cmp 'stderr' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_destination;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'stderr' }
    end
  end
end
