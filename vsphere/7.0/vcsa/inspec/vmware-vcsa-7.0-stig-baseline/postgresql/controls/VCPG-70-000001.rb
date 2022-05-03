control 'VCPG-70-000001' do
  title 'VMware Postgres must limit the number of connections.'
  desc  "
    Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources, and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

    VMware Postgres as deployed on the VCSA comes pre-configured with a max_connections limit that is appropriate for all tested, supported scenarios. The out-of-the-box configuration is dyanamic, based on a lower limit plus allowances for the resources assigned to VCSA and the deployment size. This number will always be between 100 and 1000 (inclusive), however.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW max_connections;\"

    If the returned number is not greater than or equal to 100 and less than or equal to 1000, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # vmon-cli --restart vmware-vpostgres

    Note: Restarting the service runs the \"pg_tuning\" script that will configure \"max_connections\" to the appropriate value based on the allocated memory for vCenter.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW max_connections;'

  describe sql.query(sqlquery) do
    its('output') { should cmp >= 100 }
    its('output') { should cmp <= 1000 }
  end
end
