control 'VCPG-80-000060' do
  title 'The vCenter PostgreSQL service must provide nonprivileged users with minimal error information.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to contain the minimal amount of information.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, usernames, and other system information not required for troubleshooting but very useful to someone targeting the system.'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW client_min_messages;"

Expected result:

error

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.5
  tag check_id: 'C-62920r935442_chk'
  tag severity: 'medium'
  tag gid: 'V-259180'
  tag rid: 'SV-259180r935444_rule'
  tag stig_id: 'VCPG-80-000060'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-62829r935443_fix'
  tag satisfies: ['SRG-APP-000266-DB-000162', 'SRG-APP-000267-DB-000163']
  tag cci: ['CCI-001312', 'CCI-001314']
  tag nist: ['SI-11 a', 'SI-11 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW client_min_messages;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'error' }
  end
end
