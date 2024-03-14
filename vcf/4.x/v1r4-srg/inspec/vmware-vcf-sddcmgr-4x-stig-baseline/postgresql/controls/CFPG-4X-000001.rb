control 'CFPG-4X-000001' do
  title 'The SDDC Manager PostgreSQL service must limit the number of concurrent sessions.'
  desc  'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW max_connections\"

    Expected result:

    100

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET max_connections = '100';\"
    # systemctl restart postgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-CFPG-4X-000001'
  tag rid: 'SV-CFPG-4X-000001'
  tag stig_id: 'CFPG-4X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW max_connections;'
  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_max_connections')}" }
  end
end
