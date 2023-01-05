control 'CFPG-4X-000018' do
  title 'The SDDC Manager PostgreSQL service must provide non-privileged users with minimal error information.'
  desc  "
    Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to contain the minimal amount of information.

    Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW client_min_messages\"

    Expected result:

    notice

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET client_min_messages TO 'notice';\"

    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFPG-4X-000018'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW client_min_messages;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_client_min_messages')}" }
  end
end
