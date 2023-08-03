control 'VCPG-70-000016' do
  title 'VMware Postgres must provide nonprivileged users with minimal error information.'
  desc 'Any database management system (DBMS) or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages must contain the minimal amount of information.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW client_min_messages;"

Expected result:

notice

If the output does not match the expected result, this is a finding.'
  desc 'fix', %q(At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET client_min_messages TO 'notice';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  tag check_id: 'C-60281r887602_chk'
  tag severity: 'medium'
  tag gid: 'V-256606'
  tag rid: 'SV-256606r887604_rule'
  tag stig_id: 'VCPG-70-000016'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-60224r887603_fix'
  tag satisfies: ['SRG-APP-000266-DB-000162', 'SRG-APP-000267-DB-000163']
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW client_min_messages;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_client_min_messages')}" }
  end
end
