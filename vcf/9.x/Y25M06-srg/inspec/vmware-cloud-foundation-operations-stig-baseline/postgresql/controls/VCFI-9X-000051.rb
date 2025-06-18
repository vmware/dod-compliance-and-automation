control 'VCFI-9X-000051' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must write log entries to disk prior to returning operation success or failure.'
  desc  "
    Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes.

    Aggregating log writes saves on performance but leaves a window for log data loss. The logging system inside PostgreSQL is capable of writing logs to disk, fully and completely before the associated operation is returned to the client. This ensures that database activity is always captured, even in the event of a system crash during or immediately after a given operation.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    #  su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SELECT name, setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');\\\"\"

    Example result:

    fsync              | on
    full_page_writes   | on
    synchronous_commit | on

    If the \"fsync\", \"full_page_writes\", and \"synchronous_commit\" settings are not configured to \"on\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    #  su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET <name> TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service

    Note: Substitute <name> with the incorrectly set parameter (fsync, full_page_writes, synchronous_commit).
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag gid: 'V-VCFI-9X-000051'
  tag rid: 'SV-VCFI-9X-000051'
  tag stig_id: 'VCFI-9X-000051'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query("SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');", ["#{input('postgres_default_db')}"]) do
    its('output.strip') { should match /^fsync\|on$/ }
    its('output.strip') { should match /^full_page_writes\|on$/ }
    its('output.strip') { should match /^synchronous_commit\|on$/ }
  end
end
