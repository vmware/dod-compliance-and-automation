control 'VLIC-8X-000016' do
  title 'The Aria Operations for Logs Cassandra database must verify there are no user added permissions.'
  desc  'In order to prevent unauthorized access organizations must ensure database permissions are in their shipped state and have not been altered.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    #  /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"LIST ROLES;\"

    Expected result:

     role    | super | login | options | datacenters
    ---------+-------+-------+---------+-------------
     lisuper |  True |  True |        {} |         ALL

    (1 rows)

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/bin/cqlsh-no-pass -e \"DROP ROLE <ROLE>;\"

    Note: Replace <ROLE> with each unexpected role returned from the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-VLIC-8X-000016'
  tag rid: 'SV-VLIC-8X-000016'
  tag stig_id: 'VLIC-8X-000016'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("#{input('cassandraroot')}/bin/cqlsh-no-pass -e \"SELECT role FROM system_auth.roles;\"") do
    its('stdout.strip') { should include 'lisuper' }
    its('stdout.strip') { should include '(1 rows)' }
  end
end
