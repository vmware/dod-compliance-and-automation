control 'VCPG-70-000004' do
  title 'VMware Postgres must be configured to overwrite older logs when necessary.'
  desc  'Without proper configuration, log files for VMware Postgres can grow without bound, filling the partition and potentially affecting the availability of the VCSA. One part of this configuration is to ensure that the logging subsystem overwrites, rather than appending to, any previous logs that would share the same name. This is avoided in other configuration steps but this best practice should be followed for good measure.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW log_truncate_on_rotation;\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET log_truncate_on_rotation TO 'on';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000004'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_truncate_on_rotation;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_truncate_on_rotation')}" }
  end
end
