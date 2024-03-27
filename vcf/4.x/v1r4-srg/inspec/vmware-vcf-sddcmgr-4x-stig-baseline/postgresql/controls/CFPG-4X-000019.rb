control 'CFPG-4X-000019' do
  title 'The SDDC Manager PostgreSQL service must have log collection enabled.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW logging_collector\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET logging_collector TO 'on';\"
    # systemctl restart postgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag gid: 'V-CFPG-4X-000019'
  tag rid: 'SV-CFPG-4X-000019'
  tag stig_id: 'CFPG-4X-000019'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW logging_collector;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_logging_collector')}" }
  end
end
