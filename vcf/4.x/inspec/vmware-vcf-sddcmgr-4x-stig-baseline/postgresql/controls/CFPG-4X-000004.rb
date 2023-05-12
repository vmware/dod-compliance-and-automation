control 'CFPG-4X-000004' do
  title 'The SDDC Manager PostgreSQL service must be configured to generate logs to a standard destination.'
  desc  "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -c \"SHOW log_destination\"

    Expected result:

    stderr

    If the output does not include the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_destination = 'stderr';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"

    Note: There can be more than one option set for log_destination and values should be comma separated.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-CFPG-4X-000004'
  tag rid: 'SV-CFPG-4X-000004'
  tag stig_id: 'CFPG-4X-000004'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_destination;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_destination')}" }
  end
end
