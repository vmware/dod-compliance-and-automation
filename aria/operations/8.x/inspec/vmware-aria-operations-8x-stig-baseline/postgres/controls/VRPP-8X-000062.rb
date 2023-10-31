control 'VRPP-8X-000062' do
  title 'PostgreSQL must set the default query statement timeout value to an organization-defined setting.'
  desc  'By default, PostgreSQL query statements have no timeout value set. This may lead to conditions where runaway queries can cause a denial of service.'
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c 'SHOW statement_timeout;' \"

    Example output:

    1min

    If the \"statement_timeout\" parameter is not set to a value greater than 0, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c 'ALTER SYSTEM SET statement_timeout = ''60000'';' \"

    Note: Set the parameter to the organizational requirement or use the value in the examples above, expressed in milliseconds.

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag gid: 'V-VRPP-8X-000062'
  tag rid: 'SV-VRPP-8X-000062'
  tag stig_id: 'VRPP-8X-000062'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW statement_timeout;\"'") do
    its('stdout.strip') { should_not cmp 0 }
  end
end
