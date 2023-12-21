control 'VLIC-8X-000006' do
  title 'The Aria Operations for Logs Cassandra database logs must be protected from unauthorized read access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

    This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location.

    Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

    Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c \"%a:%U:%G\" /storage/var/loginsight/cassandra.log

    Expected result:

    640:root:root

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 640 /storage/var/loginsight/cassandra.log

    # chown root:root /storage/var/loginsight/cassandra.log
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: %w(SRG-APP-000119-DB-000060 SRG-APP-000120-DB-000061)
  tag gid: 'V-VLIC-8X-000006'
  tag rid: 'SV-VLIC-8X-000006'
  tag stig_id: 'VLIC-8X-000006'
  tag cci: %w(CCI-000162 CCI-000163 CCI-000164)
  tag nist: ['AU-9']
  tag mitigations: 'This requirement is being reviewed for content and possible PR to be submitted for the seperation  of duties. This is log forward2 will provided feature where we can pass acessabiliyt and regeneration with access persmission planned for Q4. '

  describe file('/storage/var/loginsight/cassandra.log') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end
end
