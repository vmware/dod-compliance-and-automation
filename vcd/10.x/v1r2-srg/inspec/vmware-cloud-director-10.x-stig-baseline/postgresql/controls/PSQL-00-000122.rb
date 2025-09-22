control 'PSQL-00-000122' do
  title 'PostgreSQL must off-load audit data to a separate log management facility.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.

    The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.
  "
  desc  'rationale', ''
  desc  'check', "
    If logs are shipped to a syslog server via another method such as rsyslog, this is Not Applicable.

    As a database administrator, perform the following at the command prompt:

    $ psql -c \"SHOW log_destination\"

    Example result:

    syslog

    If \"log_destination\" does not include syslog, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ psql -c \"ALTER SYSTEM SET log_destination = 'syslog';\"
    $ psql -c \"ALTER SYSTEM SET syslog_facility = 'LOCAL0';\"
    $ psql -c \"ALTER SYSTEM SET syslog_ident = 'postgres';\"

    Note: There can be more than one option set for log_destination and values should be comma separated.
    Note: Configure the syslog_facility as appropriate for your environment.

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag satisfies: ['SRG-APP-000745-DB-000120', 'SRG-APP-000795-DB-000130']
  tag gid: 'V-PSQL-00-000122'
  tag rid: 'SV-PSQL-00-000122'
  tag stig_id: 'PSQL-00-000122'
  tag cci: ['CCI-001851', 'CCI-003821', 'CCI-003831']
  tag nist: ['AU-4 (1)', 'AU-6 (4)', 'AU-9 b']

  syslog_enabled = input('syslog_enabled')

  if syslog_enabled
    sql_result = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW log_destination;\"'")

    describe "Log destination - '#{sql_result.stdout.strip}'" do
      subject { sql_result.stdout.strip }
      it { should match /syslog/ }
    end
  else
    describe 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.' do
      skip 'For PostgreSQL installations that ship logs via another method such as rsyslog, this is Not Applicable.'
    end
  end
end
