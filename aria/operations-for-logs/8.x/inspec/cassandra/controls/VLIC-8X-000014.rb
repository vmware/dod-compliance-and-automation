control 'VLIC-8X-000014' do
  title 'The Aria Operations for Logs Cassandra database must verify there are no user altered roles.'
  desc  'In order to prevent unauthorized access organizations must ensure database roles are in their shipped state and have not been altered.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"SELECT role, can_login, member_of FROM system_auth.roles;\"

    Expected result:

     role    | can_login | member_of
    ---------+-----------+-----------
     lisuper |      True |      null

    (1 rows)

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command for each unexpected \"member_of\":

    # /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"REVOKE <member of> FROM <role>;\"

    Note: Replace <member of> and <role> with the unexpected \"member_of\" and \"role\" values returned from the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag satisfies: ['SRG-APP-000133-DB-000362']
  tag gid: 'V-VLIC-8X-000014'
  tag rid: 'SV-VLIC-8X-000014'
  tag stig_id: 'VLIC-8X-000014'
  tag cci: %w(CCI-000366 CCI-001499)
  tag nist: ['CM-5 (6)', 'CM-6 b']

  describe command("#{input('cassandraroot')}/bin/cqlsh-no-pass -e \"SELECT role, can_login, member_of FROM system_auth.roles;\"") do
    its('stdout.strip') { should match /lisuper\s*[|]\s*True\s*[|]\s*null/ }
    its('stdout.strip') { should include '(1 rows)' }
  end
end
