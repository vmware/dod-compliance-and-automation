control 'WOAD-3X-000001' do
  title 'The Workspace ONE Access vPostgres instance must limit the number of connections.'
  desc  "
    Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

    VMware Postgres as deployed on the WS1A comes pre-configured with a max_connections limit that is appropriate for all tested, supported scenarios. As of writing, that value is \"600\" but it may change in future releases.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW max_connections\"

    Expected result:

    600

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET max_connections TO '600';\"

    # systemctl restart vpostgres.service

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-WOAD-3X-000001'
  tag rid: 'SV-WOAD-3X-000001'
  tag stig_id: 'WOAD-3X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW max_connections;"') do
      its('stdout.strip') { should cmp '600' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW max_connections;'

    describe sql.query(sqlquery) do
      its('output') { should cmp '600' }
    end
  end
end
