control 'CFPG-4X-000023' do
  title 'The SDDC Manager PostgreSQL service must log all connection attempts.'
  desc  "For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to PostgreSQL. Setting 'log_connections' to 'on' will cause each attempted connection to the server to be logged, as well as successful completion of client authentication."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_connections\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_connections TO 'on';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag satisfies: ['SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353']
  tag gid: 'V-CFPG-4X-000023'
  tag rid: 'SV-CFPG-4X-000023'
  tag stig_id: 'CFPG-4X-000023'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_connections;'

  describe sql.query(sqlquery) do
    its('output') { should be_in "#{input('pg_log_connections')}" }
  end
end
