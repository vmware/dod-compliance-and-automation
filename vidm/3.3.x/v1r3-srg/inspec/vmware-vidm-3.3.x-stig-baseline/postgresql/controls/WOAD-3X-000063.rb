control 'WOAD-3X-000063' do
  title 'The Workspace ONE Access vPostgres instance must provide non-privileged users with minimal error information.'
  desc  "
    Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to contain the minimal amount of information.

    Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW client_min_messages\"

    Expected result:

    notice

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    #  /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET client_min_messages TO 'notice';\"

    #  /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag gid: 'V-WOAD-3X-000063'
  tag rid: 'SV-WOAD-3X-000063'
  tag stig_id: 'WOAD-3X-000063'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW client_min_messages;"') do
      its('stdout.strip') { should cmp 'notice' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW client_min_messages;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'notice' }
    end
  end
end
