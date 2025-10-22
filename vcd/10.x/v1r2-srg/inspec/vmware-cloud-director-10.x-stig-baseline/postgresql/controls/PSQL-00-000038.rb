control 'PSQL-00-000038' do
  title 'The Cloud Director PostgreSQL database must encrypt passwords for user authentication.'
  desc  "
    The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c 'SHOW password_encryption;'\"

    Expected result:

    scram-sha-256

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET password_encryption TO 'scram-sha-256';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-PSQL-00-000038'
  tag rid: 'SV-PSQL-00-000038'
  tag stig_id: 'PSQL-00-000038'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']

  sql_result = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW password_encryption;\"'")

  describe "Password encryption - '#{sql_result.stdout.strip}'" do
    subject { sql_result.stdout.strip }
    it { should cmp 'scram-sha-256' }
  end
end
