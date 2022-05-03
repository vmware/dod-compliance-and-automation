control 'VCPG-70-000010' do
  title 'The vPostgres database must use md5 for authentication.'
  desc  "
    The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

    In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW password_encryption;\"

    Expected result:

    md5

    If the output does not match the expected result, this is a finding
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET password_encryption TO 'md5';\"
    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPG-70-000010'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW password_encryption;'

  describe sql.query(sqlquery) do
    its('output') { should be_in "#{input('pg_pw_encryption')}" }
  end
end
