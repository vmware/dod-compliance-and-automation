control 'VLMP-8X-000110' do
  title 'VMware Aria Suite Lifecycle vpostgres must log all connection attempts.'
  desc  "For completeness of forensic analysis, it is necessary to track successful and failed attempts to log on to vpostgres. Setting 'log_connections' to 'on' will cause each attempted connection to the server to be logged, as well as successful completion of client authentication."
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW log_connections\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET log_connections TO 'on';\"

    Restart the vpostgres service by running the following command:

    # systemctl restart vpostgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag satisfies: ['SRG-APP-000503-DB-000351', 'SRG-APP-000506-DB-000353', 'SRG-APP-000508-DB-000358']
  tag gid: 'V-VLMP-8X-000110'
  tag rid: 'SV-VLMP-8X-000110'
  tag stig_id: 'VLMP-8X-000110'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW log_connections;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
end
