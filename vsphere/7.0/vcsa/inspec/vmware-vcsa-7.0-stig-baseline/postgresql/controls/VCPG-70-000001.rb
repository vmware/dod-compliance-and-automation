# encoding: UTF-8

control 'VCPG-70-000001' do
  title 'VMware Postgres must limit the number of connections.'
  desc  "Database management includes the ability to control the number of
users and user sessions utilizing a DBMS. Unlimited concurrent connections to
the DBMS could allow a successful Denial of Service (DoS) attack by exhausting
connection resources; and a system can also fail or be degraded by an overload
of legitimate users. Limiting the number of concurrent sessions per user is
helpful in reducing these risks.

    VMware Postgres as deployed on the VCSA comes pre-configured with a
max_connections limit that is appropriate for all tested, supported scenarios.
As of writing, that value is \"345\" but it may change in future releases.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW
max_connections;\"

    Expected result:

    384

    If the output does not match the expected result, this is a finding.

    Note: The maximum_connections is calculated on vCenter firstboot based on
VCSA allocated memory. This value may vary but it must be defined and within
reason.
  "
  desc  'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
max_connections TO '384';\"

    # vmon-cli --restart vmware-vpostgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000001'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}","#{input('postgres_pass')}","#{input('postgres_host')}")
  sqlquery = "SHOW max_connections;"
  
  describe sql.query(sqlquery) do
   its('output') {should cmp "#{input('pg_max_connections')}" }
  end

end

