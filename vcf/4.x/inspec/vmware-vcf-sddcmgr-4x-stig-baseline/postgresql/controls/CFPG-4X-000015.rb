control 'CFPG-4X-000015' do
  title 'The SDDC Manager PostgreSQL database must encrypt passwords for user authentication.'
  desc  "
    The DOD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW password_encryption\"

    Expected result:

    md5

    If the output does not match the expected result or \"on\" or \"scram-sha-256\" , this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET password_encryption TO 'md5';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: 'V-CFPG-4X-000015'
  tag rid: 'SV-CFPG-4X-000015'
  tag stig_id: 'CFPG-4X-000015'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW password_encryption;'

  describe sql.query(sqlquery) do
    its('output') { should be_in "#{input('pg_pw_encryption')}" }
  end
end
