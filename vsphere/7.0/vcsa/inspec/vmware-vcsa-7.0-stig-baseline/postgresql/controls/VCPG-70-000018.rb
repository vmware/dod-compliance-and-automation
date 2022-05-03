control 'VCPG-70-000018' do
  title 'VMware Postgres must be configured to log to stderr.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

    In order for VMware Postgres logs to be successfully sent to a remote log management system, log events must be sent to stderr. Those events will be captured and logged to disk where they will be picked up by rsyslog for shipping.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW log_destination;\"

    Expected result:

    stderr

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET log_destination TO 'stderr';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000018'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_destination;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_destination')}" }
  end
end
