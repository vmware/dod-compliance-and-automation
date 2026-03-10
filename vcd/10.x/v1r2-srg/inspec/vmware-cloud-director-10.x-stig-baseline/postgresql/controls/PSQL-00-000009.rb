control 'PSQL-00-000009' do
  title 'The Cloud Director PostgreSQL database must initiate session auditing upon startup.'
  desc  "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c 'SHOW log_destination;'\"

    Example result:

    stderr

    If \"log_destination\" is not set to stderr or syslog, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET log_destination = 'stderr';\\\"\"

    Note: There can be more than one option set for log_destination and values should be comma separated.

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-PSQL-00-000009'
  tag rid: 'SV-PSQL-00-000009'
  tag stig_id: 'PSQL-00-000009'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  sql_result = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW log_destination;\"'")

  describe "Log destination - '#{sql_result.stdout.strip}'" do
    subject { sql_result.stdout.strip }
    it { should match /(stderr|syslog)/ }
  end
end
