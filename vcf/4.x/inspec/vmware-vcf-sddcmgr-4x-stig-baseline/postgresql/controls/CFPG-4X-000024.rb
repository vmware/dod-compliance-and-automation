control 'CFPG-4X-000024' do
  title 'The SDDC Manager PostgreSQL service must log all client disconnections.'
  desc  "
    Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

    For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to PostgreSQL lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_disconnections\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_disconnections TO 'on';\"

    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFPG-4X-000024'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_disconnections;'

  describe sql.query(sqlquery) do
    its('output') { should be_in "#{input('pg_log_disconnections')}" }
  end
end
