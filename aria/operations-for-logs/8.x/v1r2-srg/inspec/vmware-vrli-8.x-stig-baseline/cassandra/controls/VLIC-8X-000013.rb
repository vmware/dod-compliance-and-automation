control 'VLIC-8X-000013' do
  title 'The Aria Operations for Logs Cassandra database must protect the truststore file.'
  desc  "
    Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.

    When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.

    Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # stat -c %a:%U:%G /usr/lib/loginsight/application/etc/truststore

    Expected result:

    600:root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command(s):

    # chmod 600 /usr/lib/loginsight/application/etc/truststore

    # chown root:root /usr/lib/loginsight/application/etc/truststore
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag gid: 'V-VLIC-8X-000013'
  tag rid: 'SV-VLIC-8X-000013'
  tag stig_id: 'VLIC-8X-000013'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  describe file('/usr/lib/loginsight/application/etc/truststore') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0600') }
  end
end
