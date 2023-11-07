control 'VCPG-80-000114' do
  title 'The vCenter PostgreSQL service must log all client disconnections.'
  desc "Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to PostgreSQL lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs."
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_disconnections;"

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
  tag check_id: 'C-62924r935454_chk'
  tag severity: 'medium'
  tag gid: 'V-259184'
  tag rid: 'SV-259184r935456_rule'
  tag stig_id: 'VCPG-80-000114'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-62833r935455_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_disconnections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
