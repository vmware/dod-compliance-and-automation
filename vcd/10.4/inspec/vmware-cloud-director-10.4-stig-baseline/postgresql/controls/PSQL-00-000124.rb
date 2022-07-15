control 'PSQL-00-000124' do
  title 'PostgreSQL must be a version supported by the vendor.'
  desc  "
    Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.
    Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

    When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -A -t -c \"SHOW server_version\"

    If postgres is not on a supported version, this is a finding.

    If postgres does not have all security relevant patches installed, this is a finding.
  "
  desc 'fix', 'Upgrade unsupported PostgreSQL components to a supported version of the product and install all security relevant patches.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000124'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  describe.one do
    # 10 is supported until November 10, 2022
    describe sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]) do
      its('output') { should match /^10/ }
    end
    # 11 is supported until November 9, 2023
    describe sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]) do
      its('output') { should match /^11/ }
    end
    # 12 is supported until November 14, 2024
    describe sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]) do
      its('output') { should match /^12/ }
    end
    # 13 is supported until November 13, 2025
    describe sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]) do
      its('output') { should match /^13/ }
    end
    # 14 is supported until November 12, 2026
    describe sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]) do
      its('output') { should match /^14/ }
    end
  end
end
