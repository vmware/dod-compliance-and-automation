control 'PSQL-00-000110' do
  title 'The Cloud Director PostgreSQL database must log all connection attempts.'
  desc  "For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to PostgreSQL. Setting 'log_connections' to 'on' will cause each attempted connection to the server to be logged, as well as successful completion of client authentication."
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c 'SHOW log_connections;'\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET log_connections TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag satisfies: ['SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353', 'SRG-APP-000508-DB-000358']
  tag gid: 'V-PSQL-00-000110'
  tag rid: 'SV-PSQL-00-000110'
  tag stig_id: 'PSQL-00-000110'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql_result = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW log_connections;\"'")

  describe "Log connections - '#{sql_result.stdout.strip}'" do
    subject { sql_result.stdout.strip }
    it { should cmp 'on' }
  end
end
