control 'VCPG-70-000011' do
  title 'VMware Postgres must be configured to use Transport Layer Security (TLS).'
  desc 'The DOD standard for authentication is DOD-approved public key infrastructure (PKI) certificates. Authentication based on user ID and password may be used only when it is not possible to employ a PKI certificate.

In such cases, passwords, must be protected at all times, and encryption is the standard method for protecting passwords during transmission.

VMware Postgres is configured out of the box to require TLS connections with remote clients. As an embedded database and available only on "localhost" for standalone vCenter Server Appliances (VCSAs), TLS connections are used only in high-availability deployments for connections between a primary and a standby. This configuration must be verified and maintained.

'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW ssl;"

Expected result:

on

If the output does not match the expected result, this is a finding.'
  desc 'fix', %q(At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl TO 'on';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  tag check_id: 'C-60276r887587_chk'
  tag severity: 'high'
  tag gid: 'V-256601'
  tag rid: 'SV-256601r887589_rule'
  tag stig_id: 'VCPG-70-000011'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-60219r887588_fix'
  tag satisfies: ['SRG-APP-000172-DB-000075', 'SRG-APP-000442-DB-000379']
  tag cci: ['CCI-000197', 'CCI-002422']
  tag nist: ['IA-5 (1) (c)', 'SC-8 (2)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW ssl;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_ssl')}" }
  end
end
