control 'PSQL-00-000007' do
  title 'PostgreSQL must generate audit records.'
  desc  "
    Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -A -t -c \"SHOW pgaudit.log_catalog\"
    $ psql -A -t -c \"SHOW pgaudit.log\"
    $ psql -A -t -c \"SHOW pgaudit.log_parameter\"
    $ psql -A -t -c \"SHOW pgaudit.log_statement_once\"
    $ psql -A -t -c \"SHOW pgaudit.log_level\"

    If \"pgaudit.log_catalog\" is not set to \"on\", this is a finding.

    If \"pgaudit.log\" is not set to \"all, -misc\", this is a finding.

    If \"pgaudit.log_parameter\" is not set to \"on\", this is a finding.

    If \"pgaudit.log_statement_once\" is not set to \"off\", this is a finding.

    If \"pgaudit.log_level\" is not set to \"log\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ psql -c \"ALTER SYSTEM SET pgaudit.log_catalog = 'on';\"
    $ psql -c \"ALTER SYSTEM SET pgaudit.log = 'all, -misc';\"
    $ psql -c \"ALTER SYSTEM SET pgaudit.log_parameter = 'on';\"
    $ psql -c \"ALTER SYSTEM SET pgaudit.log_statement_once = 'off';\"
    $ psql -c \"ALTER SYSTEM SET pgaudit.log_level = 'log';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag satisfies: ['SRG-APP-000091-DB-000325', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag gid: 'V-PSQL-00-000007'
  tag rid: 'SV-PSQL-00-000007'
  tag stig_id: 'PSQL-00-000007'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql_lc = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW pgaudit.log_catalog;\"'")

  if sql_lc.stderr.empty?
    describe "PGAudit Log catalog - '#{sql_lc.stdout.strip}'" do
      subject { sql_lc.stdout.strip }
      it { should cmp 'on' }
    end
  else
    describe 'PGAudit must be enabled for this check' do
      skip 'PGAudit must be enabled for this check'
    end
  end

  sql_log = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW pgaudit.log;\"'")

  if sql_log.stderr.empty?
    describe "PGAudit Log - '#{sql_log.stdout.strip}'" do
      subject { sql_log.stdout.strip }
      it { should cmp 'all, -misc' }
    end
  else
    describe 'PGAudit must be enabled for this check' do
      skip 'PGAudit must be enabled for this check'
    end
  end

  sql_lp = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW pgaudit.log_parameter;\"'")

  if sql_lp.stderr.empty?
    describe "PGAudit Log Parameter - '#{sql_lp.stdout.strip}'" do
      subject { sql_lp.stdout.strip }
      it { should cmp 'on' }
    end
  else
    describe 'PGAudit must be enabled for this check' do
      skip 'PGAudit must be enabled for this check'
    end
  end

  sql_lso = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW pgaudit.log_statement_once;\"'")

  if sql_lso.stderr.empty?
    describe "PGAudit Log Statement Once - '#{sql_lso.stdout.strip}'" do
      subject { sql_lso.stdout.strip }
      it { should cmp 'off' }
    end
  else
    describe 'PGAudit must be enabled for this check' do
      skip 'PGAudit must be enabled for this check'
    end
  end

  sql_ll = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW pgaudit.log_level;\"'")

  if sql_ll.stderr.empty?
    describe "PGAudit Log Level - '#{sql_ll.stdout.strip}'" do
      subject { sql_ll.stdout.strip }
      it { should cmp 'log' }
    end
  else
    describe 'PGAudit must be enabled for this check' do
      skip 'PGAudit must be enabled for this check'
    end
  end
end
