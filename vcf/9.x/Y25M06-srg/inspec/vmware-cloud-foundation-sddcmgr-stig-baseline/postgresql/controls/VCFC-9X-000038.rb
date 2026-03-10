control 'VCFC-9X-000038' do
  title 'The VMware Cloud Foundation SDDC Manager PostgreSQL service must for password-based authentication, store passwords using an approved salted key derivation function.'
  desc  "
    The DOD standard for authentication is DOD-approved PKI certificates.

    Authentication based on user ID and password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ /usr/pgsql/15/bin/psql -h localhost -U postgres -A -t -c \"SHOW password_encryption;\"

    Example result:

    scram-sha-256

    If the \"password_encryption\" setting is not configured to \"scram-sha-256\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/15/bin/psql -h localhost -U postgres -c \"ALTER SYSTEM SET password_encryption TO 'scram-sha-256';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgres
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-VCFC-9X-000038'
  tag rid: 'SV-VCFC-9X-000038'
  tag stig_id: 'VCFC-9X-000038'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW password_encryption;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'scram-sha-256' }
  end
end
