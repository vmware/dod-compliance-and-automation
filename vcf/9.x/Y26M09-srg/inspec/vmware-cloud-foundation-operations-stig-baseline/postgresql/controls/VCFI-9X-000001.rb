control 'VCFI-9X-000001' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must limit the number of concurrent sessions.'
  desc  'Database management includes the ability to control the number of users and user sessions utilizing a database management system (DBMS). Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources, and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.'
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW max_connections;'\"

    Example result:

    200

    If \"max_connections\" is set to -1 or more connections are configured than documented, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c 'ALTER SYSTEM SET max_connections = 200;'\"

    Restart the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-VCFI-9X-000001'
  tag rid: 'SV-VCFI-9X-000001'
  tag stig_id: 'VCFI-9X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW max_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should_not cmp '-1' }
    its('output') { should_not cmp '' }
    its('output') { should cmp >= 100 }
  end
end
