control 'VCPG-70-000015' do
  title 'VMware Postgres must not allow schema access to unauthorized accounts.'
  desc 'Database management systems typically separate security functionality from nonsecurity functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and nonsecurity functionality are commingled, users who have access to nonsecurity functionality may be able to access security functionality.

VMware Postgres contains a number of system configuration schemas for which access must be strictly limited. By default, the "pg_catalog" and "information_schema" objects are configured to only be accessible in a read-only manner publicly and otherwise only accessible by the Postgres user. This configuration must be verified and maintained.'
  desc 'check', %q(At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "\dp .*.;" |grep -E "information_schema|pg_catalog"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v "=r" | grep -v "^[[:space:]]*$" | grep -v "postgres"

If any lines are returned, this is a finding.)
  desc 'fix', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "REVOKE ALL PRIVILEGES ON <name> FROM <user>;"

Replace <name> and <user> with the Access Privilege name and account, respectively, discovered during the check.'
  impact 0.5
  tag check_id: 'C-60280r887599_chk'
  tag severity: 'medium'
  tag gid: 'V-256605'
  tag rid: 'SV-256605r887601_rule'
  tag stig_id: 'VCPG-70-000015'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-60223r887600_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe command("/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\dp .*.;\" |grep -E \"information_schema|pg_catalog\"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v \"=r\" | grep -v \"^[[:space:]]*$\" | grep -v \"postgres\"").stdout do
    it { should cmp '' }
  end
end
