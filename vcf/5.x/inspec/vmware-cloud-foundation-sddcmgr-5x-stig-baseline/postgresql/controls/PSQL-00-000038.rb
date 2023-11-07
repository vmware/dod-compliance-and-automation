control 'PSQL-00-000038' do
  title 'The SDDC Manager PostgreSQL service database must encrypt passwords for user authentication.'
  desc  "
    The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -A -t -c \"SHOW password_encryption\"

    Expected result:

    md5

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -c \"ALTER SYSTEM SET password_encryption TO 'md5';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgres
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-PSQL-00-000038'
  tag rid: 'SV-PSQL-00-000038'
  tag stig_id: 'PSQL-00-000038'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW password_encryption;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'md5' }
  end
end
