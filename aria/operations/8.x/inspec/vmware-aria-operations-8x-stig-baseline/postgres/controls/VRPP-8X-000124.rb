control 'VRPP-8X-000124' do
  title 'PostgreSQL must be a version supported by the vendor.'
  desc  "
    Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.
    Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

    When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c \\\"SHOW server_version;\\\"\"

    If postgres is not on a supported version, this is a finding.

    If postgres does not have all security relevant patches installed, this is a finding.
  "
  desc 'fix', 'Upgrade unsupported PostgreSQL components to a supported version of the product and install all security relevant patches.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag gid: 'V-VRPP-8X-000124'
  tag rid: 'SV-VRPP-8X-000124'
  tag stig_id: 'VRPP-8X-000124'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW server_version;\"'") do
    its('stdout.strip') { should match /^14/ }
  end
end
