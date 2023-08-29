control 'WOAD-3X-000054' do
  title 'The Workspace ONE Access vPostgres instance must write log entries to disk prior to returning operation success or failure.'
  desc  "
    Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving  system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes.

    Aggregating log writes saves on performance but leaves a window for log data loss. The logging system inside VMware Postgres is capable of writing logs to disk, fully and completely before the associated operation is returned to the client. This ensures that database activity is always captured, even in the event of a system crash during or immediately after a given operation.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');\"

    Expected result:

    fsync|on
    full_page_writes|on
    synchronous_commit|on

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following commands for each setting returned as 'off' in the check:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET <name> TO 'on';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: Substitute <name> with the incorrectly set parameter (fsync, full_page_writes, synchronous_commit)

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag gid: 'V-WOAD-3X-000054'
  tag rid: 'SV-WOAD-3X-000054'
  tag stig_id: 'WOAD-3X-000054'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']

  clustered = input('clustered')

  if clustered
    describe command("//opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');\"") do
      its('stdout.strip') { should match /^fsync\|on$/ }
      its('stdout.strip') { should match /^full_page_writes\|on$/ }
      its('stdout.strip') { should match /^synchronous_commit\|on$/ }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = "SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');"

    describe sql.query(sqlquery) do
      its('output') { should match /^fsync\|on$/ }
      its('output') { should match /^full_page_writes\|on$/ }
      its('output') { should match /^synchronous_commit\|on$/ }
    end
  end
end
