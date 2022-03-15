control 'VCPG-67-000015' do
  title 'VMware Postgres must use FIPS 140-2 approved TLS ciphers.'
  desc  "Use of weak or unvalidated cryptographic algorithms undermines the
purposes of using encryption and digital signatures to protect data. Weak
algorithms can be broken, and unvalidated cryptographic modules may not
implement algorithms correctly. Unapproved cryptographic modules or algorithms
should not be relied on for authentication, confidentiality, or integrity. Weak
cryptography could allow an attacker to gain access to and modify data stored
in the database as well as the administration settings of the DBMS.

    VMware Postgres does not currently implement FIPS-validated cryptographic
modules. This is on the roadmap but, in the interim, Postgres can be configured
with strong ciphers from the FIPS 140 approved suite. Additionally, as an
embedded database and available only on localhost for standalone VCSAs, TLS
connections are used only in high-availability deployments for connections
between a primary and a standby.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SHOW
ssl_ciphers;\"|sed -n 3p|sed -e 's/^[ ]*//'

    Expected result:

    !aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
ssl_ciphers TO '!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag satisfies: %w(SRG-APP-000179-DB-000114 SRG-APP-000514-DB-000381
SRG-APP-000514-DB-000382 SRG-APP-000514-DB-000383)
  tag gid: 'V-239207'
  tag rid: 'SV-239207r717058_rule'
  tag stig_id: 'VCPG-67-000015'
  tag fix_id: 'F-42399r678993_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW ssl_ciphers;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_ssl_ciphers')}" }
  end
end
