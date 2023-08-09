control 'VCPG-70-000012' do
  title 'VMware Postgres must enforce authorized access to all public key infrastructure (PKI) private keys.'
  desc "The DOD standard for authentication is DOD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If a private key is stolen, an attacker can use it to impersonate the certificate holder. In cases where the database management system (DBMS)-stored private keys are used to authenticate the DBMS to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man-in-the-middle attacks against the DBMS system and its clients.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users."
  desc 'check', 'At the command prompt, run the following command:

# stat -c "%a:%U:%G" /storage/db/vpostgres_ssl/server.key

Expected result:

600:vpostgres:vpgmongrp

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command prompt, run the following commands:

# chmod 600 /storage/db/vpostgres_ssl/server.key
# chown vpostgres:vpgmongrp /storage/db/vpostgres_ssl/server.key'
  impact 0.7
  tag check_id: 'C-60277r887590_chk'
  tag severity: 'high'
  tag gid: 'V-256602'
  tag rid: 'SV-256602r887592_rule'
  tag stig_id: 'VCPG-70-000012'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-60220r887591_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']

  describe file("#{input('pg_ssl_key')}") do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'vpostgres' }
    its('group') { should cmp 'vpgmongrp' }
  end
end
