control 'CFCS-5X-000088' do
  title 'The SDDC Manager Common Services service must restrict changes to application server configuration.'
  desc  "
    When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software, and/or application server configuration can potentially have significant effects on the overall security of the system.

    Access restrictions for changes also include application software libraries.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/vcf/commonsvcs/conf -xdev -type f -a '(' -perm /177 -o -not -user vcf_commonsvcs -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned in the output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod 400 <file>
    # chmod vcf_commonsvcs:vcf <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag satisfies: ['SRG-APP-000121-AS-000081', 'SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000340-AS-000185']
  tag gid: 'V-CFCS-5X-000088'
  tag rid: 'SV-CFCS-5X-000088'
  tag stig_id: 'CFCS-5X-000088'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'AU-9', 'AU-9 a', 'CM-5 (1) (a)']

  appfiles = command('find /opt/vmware/vcf/commonsvcs/conf -xdev -type f').stdout
  if !appfiles.empty?
    appfiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_more_permissive_than('0600') }
        its('owner') { should cmp 'vcf_commonsvcs' }
        its('group') { should cmp 'vcf' }
      end
    end
  else
    describe 'No app files found...skipping.' do
      skip 'No app files found...skipping.'
    end
  end
end
