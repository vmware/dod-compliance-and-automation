control 'VCPG-70-000013' do
  title 'VMware Postgres must use FIPS 140-2 approved Transport Layer Security (TLS) ciphers.'
  desc 'Use of weak or unvalidated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be broken, and unvalidated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the database management system (DBMS).

VMware Postgres does not currently implement FIPS-validated cryptographic modules. This is planned but, in the interim, Postgres can be configured with strong ciphers from the FIPS-140 approved suite. Additionally, as an embedded database available only on "localhost" for a standalone vCenter Server Appliance, TLS connections are used only in high-availability deployments for connections between a primary and a standby.

'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW ssl_ciphers;"

Expected result:

!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH

If the output does not match the expected result, this is a finding.'
  desc 'fix', %q(At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_ciphers TO '!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  tag check_id: 'C-60278r887593_chk'
  tag severity: 'high'
  tag gid: 'V-256603'
  tag rid: 'SV-256603r887595_rule'
  tag stig_id: 'VCPG-70-000013'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-60221r887594_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383']
  tag cci: ['CCI-000803', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW ssl_ciphers;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_ssl_ciphers')}" }
  end
end
