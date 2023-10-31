control 'WOAD-3X-000031' do
  title 'The Workspace ONE Access vPostgres tables in the "saas" database must be owned by the "horizon" user.'
  desc  "
    Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

    The saas database tables are configured out of the box to be owned by the 'horizon' Postgres user. This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -d saas -x -U postgres -c \"\\dt;\"|grep Owner|grep -v horizon

    If any tables are returned, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER TABLE <tablename> OWNER TO horizon;\"

    Replace <tablename> with the name of the table discovered during the check.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-WOAD-3X-000031'
  tag rid: 'SV-WOAD-3X-000031'
  tag stig_id: 'WOAD-3X-000031'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -d saas -x -U postgres -c \"\\dt;\"|grep Owner|grep -v horizon') do
      its('stdout.strip') { should cmp '' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = "select tablename,tableowner from pg_tables where schemaname = 'saas' and tableowner != 'horizon';"

    describe sql.query(sqlquery, ['saas']) do
      its('output') { should cmp '' }
    end
  end
end
