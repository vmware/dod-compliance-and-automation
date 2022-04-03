control 'VCPG-67-000014' do
  title "VMware Postgres must enforce authorized access to all PKI private
keys."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
PKI certificate-based authentication is performed by requiring the certificate
holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to
impersonate the certificate holder.  In cases where the DBMS-stored private
keys are used to authenticate the DBMS to the system’s clients, loss of the
corresponding private keys would allow an attacker to successfully perform
undetected man-in-the-middle attacks against the DBMS system and its clients.

    All access to the private key(s) of the DBMS must be restricted to
authorized and authenticated users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%a:%U:%G\" /storage/db/vpostgres_ssl/server.key

    Expected result:

    600:vpostgres:users

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # chmod 600 /storage/db/vpostgres_ssl/server.key
    # chown vpostgres:users /storage/db/vpostgres_ssl/server.key
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag gid: 'V-239206'
  tag rid: 'SV-239206r717057_rule'
  tag stig_id: 'VCPG-67-000014'
  tag fix_id: 'F-42398r678990_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  describe file("#{input('pg_ssl_key')}") do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'vpostgres' }
    its('group') { should cmp 'users' }
  end
end
