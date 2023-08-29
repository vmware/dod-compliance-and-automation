control 'WOAD-3X-000074' do
  title 'The Workspace ONE Access vPostgres instance must have log collection enabled.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

    VMware Postgres is capable of outputting directly to syslog but for performance reasons, the VCSA is configured to ship logs centrally via rsyslog file monitoring. In order to facilitate that configuration, log files must be generated to disk.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW logging_collector\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET logging_collector TO 'on';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag satisfies: ['SRG-APP-000356-DB-000315', 'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000333', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357', 'SRG-APP-000508-DB-000358', 'SRG-APP-000514-DB-000381']
  tag gid: 'V-WOAD-3X-000074'
  tag rid: 'SV-WOAD-3X-000074'
  tag stig_id: 'WOAD-3X-000074'
  tag cci: ['CCI-000172', 'CCI-001814', 'CCI-001844', 'CCI-002450']
  tag nist: ['AU-12 c', 'AU-3 (2)', 'CM-5 (1)', 'SC-13']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW logging_collector;"') do
      its('stdout.strip') { should cmp 'on' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW logging_collector;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'on' }
    end
  end
end
