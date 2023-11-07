control 'VCPG-80-000009' do
  title 'The vCenter PostgreSQL service must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the database management system (DBMS) is running."
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_destination;"

Example result:

stderr

If "log_destination" is not set to "stderr" or "syslog", this is a finding.'
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.5
  tag check_id: 'C-62910r935412_chk'
  tag severity: 'medium'
  tag gid: 'V-259170'
  tag rid: 'SV-259170r935414_rule'
  tag stig_id: 'VCPG-80-000009'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-62819r935413_fix'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_destination;', ["#{input('postgres_default_db')}"]) do
    its('output') { should match /(stderr|syslog)/ }
  end
end
