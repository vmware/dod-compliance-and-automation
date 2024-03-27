control 'VCPG-70-000006' do
  title 'All vCenter database (VCDB) tables must be owned by the "vc" user account.'
  desc %q(Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who uses the object to perform the actions if they are the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

VCDB is configured out of the box to be owned by the "vc" Postgres user. This configuration must be verified and maintained.)
  desc 'check', %q(At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -t -A -c "\dt;" | grep -v 'table|vc'

If any tables are returned, this is a finding.

Note: Upgrades may introduce new tables that are owned by the "postgres" user and can be updated to be owned by the "vc" user.)
  desc 'fix', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -c "ALTER TABLE <tablename> OWNER TO vc;"

Replace <tablename> with the name of the table discovered during the check.'
  impact 0.5
  tag check_id: 'C-60271r918969_chk'
  tag severity: 'medium'
  tag gid: 'V-256596'
  tag rid: 'SV-256596r918971_rule'
  tag stig_id: 'VCPG-70-000006'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-60214r918970_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = "select tablename,tableowner from pg_tables where schemaname = 'vc' AND tableowner != 'vc';"
  db = 'VCDB'

  describe sql.query(sqlquery, [db]) do
    its('output') { should cmp '' }
  end
end
