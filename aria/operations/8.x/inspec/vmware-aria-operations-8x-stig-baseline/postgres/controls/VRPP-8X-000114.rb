control 'VRPP-8X-000114' do
  title 'PostgreSQL must log all client disconnections.'
  desc  "
    Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged.

    For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to PostgreSQL lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c \\\"SHOW log_disconnections;\\\"\"

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c \\\"ALTER SYSTEM SET log_disconnections TO 'on';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag gid: 'V-VRPP-8X-000114'
  tag rid: 'SV-VRPP-8X-000114'
  tag stig_id: 'VRPP-8X-000114'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW log_disconnections;\"'") do
    its('stdout.strip') { should cmp 'on' }
  end
end
