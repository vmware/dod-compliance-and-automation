control 'VCPG-80-000110' do
  title 'The vCenter PostgreSQL service must log all connection attempts.'
  desc 'For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to PostgreSQL. Setting "log_connections" to "on" will cause each attempted connection to the server to be logged, as well as successful completion of client authentication.'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_connections;"

Expected result:

on

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.5
  tag check_id: 'C-62923r935451_chk'
  tag severity: 'medium'
  tag gid: 'V-259183'
  tag rid: 'SV-259183r935453_rule'
  tag stig_id: 'VCPG-80-000110'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-62832r935452_fix'
  tag satisfies: ['SRG-APP-000503-DB-000350', 'SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353', 'SRG-APP-000508-DB-000358']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
