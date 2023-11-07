control 'VCPG-80-000001' do
  title 'The vCenter PostgreSQL service must limit the number of concurrent sessions.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a database management system (DBMS). Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources, and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

VMware Postgres as deployed on the vCenter Service Appliance (VCSA) comes preconfigured with a "max_connections" limit that is appropriate for all tested, supported scenarios. The out-of-the-box configuration is dynamic, based on a lower limit plus allowances for the resources assigned to VCSA and the deployment size. However, this number will always be between 100 and 1000 (inclusive).'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW max_connections;"

If the returned number is not greater than or equal to 100 and less than or equal to 1000, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# vmon-cli --restart vmware-vpostgres

Note: Restarting the service runs the "pg_tuning" script that will configure "max_connections" to the appropriate value based on the allocated memory for vCenter.'
  impact 0.5
  tag check_id: 'C-62906r935400_chk'
  tag severity: 'medium'
  tag gid: 'V-259166'
  tag rid: 'SV-259166r935402_rule'
  tag stig_id: 'VCPG-80-000001'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-62815r935401_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  describe sql.query('SHOW max_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should_not cmp '-1' }
    its('output') { should_not cmp '' }
  end
end
