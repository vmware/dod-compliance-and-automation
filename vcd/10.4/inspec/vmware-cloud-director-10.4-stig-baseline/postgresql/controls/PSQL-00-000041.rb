control 'PSQL-00-000041' do
  title 'PostgreSQL must enforce authorized access to all PKI private keys stored/utilized by PostgreSQL.'
  desc  "
    The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder.  In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the DBMS system and its clients.

    Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

    All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions.
  "
  desc  'rationale', ''
  desc  'check', "
    For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.

    As a database administrator, perform the following at the command prompt to find the current location of the private key users for SSL connections:

    $ psql -A -t -c \"SHOW ssl_key_file\"
    $ stat -c \"%n is owned by %U:%G with permissions of %a\" <ssl_key_file path>

    Example output:

    /etc/postgres/cert.key is owned by postgres:postgres with permissions of 600

    If the SSL key file is not owned by the user postgres and group postgres, this is a finding.

    If the SSL key file has permissions more permissive than 0600, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command(s):

    # chmod 600 <file>
    # chown postgres:postgres <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000041'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  ssl_enabled = input('ssl_enabled')

  if ssl_enabled
    pg_ssl_key = input('pg_ssl_key')
    pg_owner = input('pg_owner')
    pg_group = input('pg_group')

    sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

    describe sql.query('SHOW ssl_key_file;', ["#{input('postgres_default_db')}"]) do
      its('output') { should cmp pg_ssl_key }
    end

    describe file(pg_ssl_key) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  else
    describe 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.' do
      skip 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.'
    end
  end
end
