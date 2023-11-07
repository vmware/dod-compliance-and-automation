control 'PSQL-00-000060' do
  title 'The SDDC Manager PostgreSQL service must provide non-privileged users with minimal error information.'
  desc  "
    Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to contain the minimal amount of information.

    Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -A -t -c \"SHOW client_min_messages\"

    Expected result:

    error

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -c \"ALTER SYSTEM SET client_min_messages TO 'error';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag satisfies: ['SRG-APP-000267-DB-000163']
  tag gid: 'V-PSQL-00-000060'
  tag rid: 'SV-PSQL-00-000060'
  tag stig_id: 'PSQL-00-000060'
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW client_min_messages;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'error' }
  end
end
