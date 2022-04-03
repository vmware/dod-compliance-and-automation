control 'VCPG-67-000017' do
  title 'VMware Postgres must not allow schema access to unauthorized accounts.'
  desc  "Database management systems typically separate security functionality
from non-security functionality via separate databases or schemas. Database
objects or code implementing security functionality should not be commingled
with objects or code implementing application logic. When security and
non-security functionality are commingled, users who have access to
non-security functionality may be able to access security functionality.

    VMware Postgres contains a number of system configuration schema whose
access must be strictly limited. By default, the pg_catalog and
information_schema objects are configured to only be accessible in a read-only
manner publicly, and otherwise only accessible by the Postgres user. This
configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\dp
.*.;\"/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\dp .*.;\"|grep
-E \"information_schema|pg_catalog\"|awk -F '|' '{print $4}'|awk -F '/' '{print
$1}'|grep -v \"=r\"|grep -v \"postgres\"|grep -v \"  \"

    If any lines are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"REVOKE ALL
PRIVILEGES ON <name> FROM <user>;\"

    Replace <name> and <user> with the Access Privilege name and account,
respectively, discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag gid: 'V-239209'
  tag rid: 'SV-239209r717061_rule'
  tag stig_id: 'VCPG-67-000017'
  tag fix_id: 'F-42401r678999_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe command("psql -U postgres -c '\\dp .*.;' | awk -F'|' '{print $4}' | grep -v 'Access' | sed -r '/^\s*$/d' | cut -d'+' -f1 | grep -v -E 'postgres=|=r|w/postgres'") do
    its('stdout.strip') { should cmp '' }
  end
end
