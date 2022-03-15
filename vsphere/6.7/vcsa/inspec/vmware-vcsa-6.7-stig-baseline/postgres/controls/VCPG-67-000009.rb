control 'VCPG-67-000009' do
  title 'VMware Postgres must limit modify privileges to authorized accounts.'
  desc  "If VMware Postgres were to allow any user to make changes to database
structure or logic, those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    Accordingly, only qualified and authorized individuals must be allowed to
obtain access to information system components to initiate changes, including
upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or
configuration can lead to unauthorized or compromised installations.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\du;\"|grep
\"Create\"

    Expected result:

     postgres   | Superuser, Create role, Create DB, Replication, Bypass RLS |
{}
     vc         | Create DB                                                  |
{}

    If the accounts other than \"postgres\" and \"vc\" have any \"Create\"
privileges, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"REVOKE ALL
PRIVILEGES FROM <user>;\"

    Replace <user> with the account discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag gid: 'V-239202'
  tag rid: 'SV-239202r717054_rule'
  tag stig_id: 'VCPG-67-000009'
  tag fix_id: 'F-42394r678978_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe postgres_session('postgres', '', 'localhost').query("SELECT * FROM pg_roles WHERE rolcreatedb = \'t\' or rolcreaterole = \'t\';") do
    its('output.strip') { should match /^postgres.*$/ }
    its('output.strip') { should match /^vc.*$/ }
  end
end
