control 'VCFL-9X-000001' do
  title 'The VMware Cloud Foundation vCenter PostgreSQL service must limit the number of concurrent sessions.'
  desc  "
    Database management includes the ability to control the number of users and user sessions utilizing a database management system (DBMS). Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources, and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

    VMware Postgres as deployed on the vCenter Service Appliance (VCSA) comes preconfigured with a \"max_connections\" limit that is appropriate for all tested, supported scenarios. The out-of-the-box configuration is dynamic, based on a lower limit plus allowances for the resources assigned to VCSA and the deployment size. However, this number will always be between 100 and 1000 (inclusive).
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW max_connections;\"

    Example result:

    100

    If the \"max_connections\" setting is not configured to greater than or equal to 100 or less than or equal to 1000, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # vmon-cli --restart vmware-vpostgres

    Note: Restarting the service runs the \"pg_tuning\" script that will configure \"max_connections\" to the appropriate value based on the allocated memory for vCenter.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-VCFL-9X-000001'
  tag rid: 'SV-VCFL-9X-000001'
  tag stig_id: 'VCFL-9X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  describe sql.query('SHOW max_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should_not cmp '-1' }
    its('output') { should_not cmp '' }
    its('output') { should cmp <= 1000 }
    its('output') { should cmp >= 100 }
  end
end
