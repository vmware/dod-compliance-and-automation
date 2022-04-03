control 'VCPG-67-000020' do
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
file monitoring. To facilitate that configuration, log files must be generated
to disk.
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
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
logging_collector TO 'on';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag satisfies: ['SRG-APP-000356-DB-000314', 'SRG-APP-000356-DB-000315',
'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000333',
'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327',
'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329',
'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335',
'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331',
'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337',
'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355',
'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357',
'SRG-APP-000508-DB-000358', 'SRG-APP-000492-DB-000332',
'SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353']
  tag gid: 'V-239212'
  tag rid: 'SV-239212r717063_rule'
  tag stig_id: 'VCPG-67-000020'
  tag fix_id: 'F-42404r679008_fix'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW logging_collector;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_logging_collector')}" }
  end
end
