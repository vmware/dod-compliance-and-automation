# encoding: UTF-8

control 'VCPG-70-000017' do
  title 'VMware Postgres must have log collection enabled.'
  desc  "Without the ability to centrally manage the content captured in the
audit records, identification, troubleshooting, and correlation of suspicious
behavior would be difficult and could lead to a delayed or incomplete analysis
of an ongoing attack.

    The content captured in audit records must be managed from a central
location (necessitating automation). Centralized management of audit records
and logs provides for efficiency in maintenance and management of records, as
well as the backup and archiving of those records.

    VMware Postgres is capable of outputting directly to syslog but for
performance reasons, the VCSA is configured to ship logs centrally via rsyslog
file monitoring. In order to facilitate that configuration, log files must be
generated to disk.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SHOW
logging_collector;\"|sed -n 3p|sed -e 's/^[ ]*//'

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
logging_collector TO 'on';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000017'
  tag fix_id: nil
  tag cci: 'CCI-001844'
  tag nist: ['AU-3 (2)']

  sql = postgres_session("#{input('postgres_user')}","#{input('postgres_pass')}","#{input('postgres_host')}")
  sqlquery = "SHOW logging_collector;"
  
  describe sql.query(sqlquery) do
   its('output') {should cmp "#{input('pg_logging_collector')}" }
  end

end

