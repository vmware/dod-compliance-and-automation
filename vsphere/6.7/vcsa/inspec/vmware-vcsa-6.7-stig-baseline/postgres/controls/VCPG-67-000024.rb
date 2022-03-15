control 'VCPG-67-000024' do
  title 'VMware Postgres must set client-side character encoding to UTF-8.'
  desc  "A common vulnerability is unplanned behavior when invalid inputs are
received. This requirement guards against adverse or unintended system behavior
caused by invalid inputs, where information system responses to the invalid
input may be disruptive or cause the system to fail to an unsafe state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SHOW
client_encoding;\"|sed -n 3p|sed -e 's/^[ ]*//'

    Expected result:

    UTF8

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
client_encoding TO 'UTF8';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag gid: 'V-239216'
  tag rid: 'SV-239216r717067_rule'
  tag stig_id: 'VCPG-67-000024'
  tag fix_id: 'F-42408r679020_fix'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW client_encoding;'

  describe sql.query(sqlquery) do
    its('output') { should be_in "#{input('pg_client_encoding')}" }
  end
end
