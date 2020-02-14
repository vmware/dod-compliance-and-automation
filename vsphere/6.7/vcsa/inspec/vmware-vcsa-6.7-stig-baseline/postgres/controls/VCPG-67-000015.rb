control "VCPG-67-000015" do
  title "The DBMS must use NIST FIPS 140-2 validated cryptographic modules for
cryptographic operations."
  desc  "Use of weak or not validated cryptographic algorithms undermines the
purposes of utilizing encryption and digital signatures to protect data.  Weak
algorithms can be easily broken and not validated cryptographic modules may not
implement algorithms correctly. Unapproved cryptographic modules or algorithms
should not be relied on for authentication, confidentiality or integrity. Weak
cryptography could allow an attacker to gain access to and modify data stored
in the database as well as the administration settings of the DBMS.

    Applications, including DBMSs, utilizing cryptography are required to use
approved NIST FIPS 140-2 validated cryptographic modules that meet the
requirements of applicable federal laws, Executive Orders, directives,
policies, regulations, standards, and guidance.

    The security functions validated as part of FIPS 140-2 for cryptographic
modules are described in FIPS 140-2 Annex A.

    NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
encryption modules."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000179-DB-000114"
  tag gid: nil
  tag rid: "VCPG-67-000015"
  tag stig_id: "VCPG-67-000015"
  tag cci: "CCI-000803"
  tag nist: ["IA-7", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*ssl_ciphers\\b' /storage/db/vpostgres/postgresql.conf

If \"ssl_ciphers\" is not \"!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH\", this
is a finding:

"
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
ssl_ciphers TO 'FIPS: +3DES:!aNULL';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('ssl_ciphers') { should eq "'!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH'" }
  end

end

