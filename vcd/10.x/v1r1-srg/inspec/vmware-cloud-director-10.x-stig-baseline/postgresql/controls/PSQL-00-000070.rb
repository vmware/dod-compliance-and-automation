control 'PSQL-00-000070' do
  title 'PostgreSQL must have log collection enabled.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -A -t -c \"SHOW logging_collector\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ psql  c \"ALTER SYSTEM SET logging_collector TO 'on';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag satisfies: ['SRG-APP-000381-DB-000361']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000070'
  tag cci: ['CCI-001844', 'CCI-001814']
  tag nist: ['AU-3 (2)', 'CM-5 (1)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW logging_collector;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
