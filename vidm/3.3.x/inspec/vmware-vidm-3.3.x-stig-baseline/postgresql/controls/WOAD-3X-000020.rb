control 'WOAD-3X-000020' do
  title 'The Workspace ONE Access vPostgres instance must be configured to overwrite older logs when necessary.'
  desc  'Without proper configuration, log files for VMware Postgres can grow without bound, filling the partition and potentially affecting the availability of the WS1A. One part of this configuration is to ensure that the logging subsystem overwrites, rather than appending to, any previous logs that would share the same name. This is avoided in other configuration steps but this best practice should be followed for good measure.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_truncate_on_rotation;\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_truncate_on_rotation TO 'on';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag gid: 'V-WOAD-3X-000020'
  tag rid: 'SV-WOAD-3X-000020'
  tag stig_id: 'WOAD-3X-000020'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_truncate_on_rotation;"') do
      its('stdout.strip') { should cmp 'on' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_truncate_on_rotation;'

    describe sql.query(sqlquery) do
      its('output') { should cmp 'on' }
    end
  end
end
