control 'VRPP-8X-000041' do
  title 'VMware Aria Operations vPostgres must enforce authorized access to all PKI private keys stored/utilized by vPostgres.'
  desc  "
    The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder.  In cases where the database-stored private keys are used to authenticate vPostgres to clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the system and its clients.

    Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

    All access to the private key(s) of the database must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions.
  "
  desc  'rationale', ''
  desc  'check', "
    For vPostgres installations that are not accessible over the network and do not have SSL turned on, this control is Not Applicable.

    As a database administrator, perform the following at the command prompt to find the current location of the private key users for SSL connections:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW ssl_key_file;\\\"\"
    $ stat -c \"%n is owned by %U:%G with permissions of %a\" <ssl_key_file path>

    Example output:

    /var/vmware/vpostgres/current/vpostgres_key.pem is owned by postgres:users with permissions of 400

    If the SSL key file is not owned by the user postgres and group users, this is a finding.

    If the SSL key file has permissions more permissive than 0400, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command(s):

    # chmod 400 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag gid: 'V-VRPP-8X-000041'
  tag rid: 'SV-VRPP-8X-000041'
  tag stig_id: 'VRPP-8X-000041'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']

  ssl_enabled = input('ssl_enabled')

  if ssl_enabled
    pg_owner = input('pg_owner')
    pg_group = input('pg_group')
    pg_ssl_key = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW ssl_key_file;\"'").stdout.strip

    describe pg_ssl_key do
      it { should_not be_empty }
    end

    describe file(pg_ssl_key) do
      its('mode') { should cmp '0400' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  else
    describe 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.' do
      skip 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.'
    end
  end
end
