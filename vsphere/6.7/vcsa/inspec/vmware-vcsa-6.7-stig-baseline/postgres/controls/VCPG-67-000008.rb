control 'VCPG-67-000008' do
  title 'All VCDB tables must be owned by the "vc" user account.'
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who uses the object to perform the actions if they
were the owner. If not properly managed, this can lead to privileged actions
being taken by unauthorized individuals.

    VCDB is configured out of the box to be owned by the \"vc\" Postgres user.
This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -d VCDB -x -U postgres -c
\"\\dt;\"|grep Owner|grep -v vc

    If any tables are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER TABLE
<tablename> OWNER TO vc;\"

    Replace <tablename> with the name of the table discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-239201'
  tag rid: 'SV-239201r717053_rule'
  tag stig_id: 'VCPG-67-000008'
  tag fix_id: 'F-42393r678975_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = "select tablename,tableowner from pg_tables where schemaname = 'vc' AND tableowner != 'vc';"
  db = 'VCDB'

  describe sql.query(sqlquery, [db]) do
    its('output') { should cmp '' }
  end
end
