control 'VLIC-8X-000007' do
  title 'The Aria Operations for Logs Cassandra database log configuration file must be protected from unauthorized read access.'
  desc  "
    Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.

    Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

    Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

    If an attacker were to gain access to audit tools, they could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c \"%a:%U:%G\" /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/conf/cassandra.yaml

    Expected result:

    640:root:root

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/conf/cassandra.yaml

    # chown root:root /usr/lib/loginsight/application/lib/apache-cassandra-<VERSION>/conf/cassandra.yaml
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag gid: 'V-VLIC-8X-000007'
  tag rid: 'SV-VLIC-8X-000007'
  tag stig_id: 'VLIC-8X-000007'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9']
  tag mitigations: 'This requirement is being reviewed for content and possible PR to be submitted for the seperation  of duties. This is log forward2 will provided feature where we can pass acessabiliyt and regeneration with access persmission planned for Q4. '

  describe file("#{input('cassandraroot')}/conf/cassandra.yaml") do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end
end
