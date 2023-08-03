control 'VCPG-70-000004' do
  title 'VMware Postgres must be configured to overwrite older logs when necessary.'
  desc 'Without proper configuration, log files for VMware Postgres can grow without bound, filling the partition and potentially affecting the availability of the vCenter Server Appliance (VCSA). One part of this configuration is to ensure the logging subsystem overwrites, rather than appends to, any previous logs that would share the same name. This is avoided in other configuration steps, but this best practice should be followed for good measure.'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW log_truncate_on_rotation;"

Expected result:

on

If the output does not match the expected result, this is a finding.'
  desc 'fix', %q(At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_truncate_on_rotation TO 'on';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  tag check_id: 'C-60269r887566_chk'
  tag severity: 'medium'
  tag gid: 'V-256594'
  tag rid: 'SV-256594r887568_rule'
  tag stig_id: 'VCPG-70-000004'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-60212r887567_fix'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_truncate_on_rotation;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_truncate_on_rotation')}" }
  end
end
