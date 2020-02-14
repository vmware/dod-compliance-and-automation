control "VCPG-67-000014" do
  title "The vPostgres database must enforce authorized access to all PKI
private keys stored/utilized by the DBMS."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
PKI certificate-based authentication is performed by requiring the certificate
holder to cryptographically prove possession of the corresponding private key.

    If the private key is stolen, an attacker can use the private key(s) to
impersonate the certificate holder.  In cases where the DBMS-stored private
keys are used to authenticate the DBMS to the system\xE2\x80\x99s clients, loss
of the corresponding private keys would allow an attacker to successfully
perform undetected man in the middle attacks against the DBMS system and its
clients.

    Both the holder of a digital certificate and the issuing authority must
take careful measures to protect the corresponding private key. Private keys
should always be generated and protected in FIPS 140-2 validated cryptographic
modules.

    All access to the private key(s) of the DBMS must be restricted to
authorized and authenticated users. If unauthorized users have access to one or
more of the DBMS's private keys, an attacker could gain access to the key(s)
and use them to impersonate the database on the network or otherwise perform
unauthorized actions."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000176-DB-000068"
  tag gid: nil
  tag rid: "VCPG-67-000014"
  tag stig_id: "VCPG-67-000014"
  tag cci: "CCI-000186"
  tag nist: ["IA-5 (2) (b)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# stat -c \"%n permissions are %a\" /storage/db/vpostgres_ssl/server.key

If the permissions on server.key are not 600, this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# chmod 600 /storage/db/vpostgres_ssl/server.key"

  describe file('/storage/db/vpostgres_ssl/server.key') do
    its('mode') { should cmp '0600' }
  end

end

