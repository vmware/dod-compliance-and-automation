control 'PSQL-00-000029' do
  title 'The SDDC Manager PostgreSQL service objects must be owned by principals authorized for ownership.'
  desc  "
    Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -d domainmanager -x -c \"\\dt\" | grep Owner | grep -v domainmanager

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -d lcm -x -c \"\\dt\" | grep Owner | grep -v lcm

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -d operationsmanager -x -c \"\\dt\" | grep Owner | grep -v opsmgr

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -d platform -x -c \"\\dt\" | grep Owner | grep -v platform

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -d sddc_manager_ui -x -c \"\\dt\" | grep Owner | grep -v vcfui

    If any results are returned from any of the commands, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -c \"ALTER TABLE <tablename> OWNER TO <ownername>;\"

    Replace <tablename> with the name of the table discovered during the check and <ownername> with the appropriate owner name from the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-PSQL-00-000029'
  tag rid: 'SV-PSQL-00-000029'
  tag stig_id: 'PSQL-00-000029'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  sqlquerydm = "select tablename,tableowner from pg_tables where schemaname = 'public' AND tableowner != 'domainmanager';"
  dbdm = 'domainmanager'

  describe sql.query(sqlquerydm, [dbdm]) do
    its('output') { should cmp '' }
  end

  sqlquerylcm = "select tablename,tableowner from pg_tables where schemaname = 'public' AND tableowner != 'lcm';"
  dblcm = 'lcm'

  describe sql.query(sqlquerylcm, [dblcm]) do
    its('output') { should cmp '' }
  end

  sqlqueryom = "select tablename,tableowner from pg_tables where schemaname = 'public' AND tableowner != 'opsmgr';"
  dbom = 'operationsmanager'

  describe sql.query(sqlqueryom, [dbom]) do
    its('output') { should cmp '' }
  end

  sqlquerypl = "select tablename,tableowner from pg_tables where schemaname = 'public' AND tableowner != 'platform';"
  dbpl = 'platform'

  describe sql.query(sqlquerypl, [dbpl]) do
    its('output') { should cmp '' }
  end

  sqlqueryui = "select tablename,tableowner from pg_tables where schemaname = 'public' AND tableowner != 'vcfui';"
  dbui = 'sddc_manager_ui'

  describe sql.query(sqlqueryui, [dbui]) do
    its('output') { should cmp '' }
  end
end
