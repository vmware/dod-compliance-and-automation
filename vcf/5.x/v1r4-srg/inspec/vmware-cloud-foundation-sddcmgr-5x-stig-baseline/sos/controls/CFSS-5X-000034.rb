control 'CFSS-5X-000034' do
  title 'The SDDC Manager SOS service must limit privileges to change the software resident within software libraries.'
  desc  'The application server should limit the ability of non-privileged users to modify any application libraries, scripts, or configuration files. The application files must be adequately protected with correct permissions as applied "out of the box".'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/sddc-support -xdev -path /opt/vmware/sddc-support/__pycache__ -prune -o '(' -perm -o+w -o -not -user vcf_sos -o -not -group vcf ')' -type f -exec ls -ld {} \\;

    If any files are returned in the output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chmod vcf_sos:vcf <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag satisfies: ['SRG-APP-000121-AS-000081', 'SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000340-AS-000185', 'SRG-APP-000380-AS-000088']
  tag gid: 'V-CFSS-5X-000034'
  tag rid: 'SV-CFSS-5X-000034'
  tag stig_id: 'CFSS-5X-000034'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001499', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-6 (10)', 'AU-9', 'AU-9 a', 'CM-5 (1) (a)', 'CM-5 (6)']

  describe command('find /opt/vmware/sddc-support -xdev -path /opt/vmware/sddc-support/__pycache__ -prune -o \'(\' -perm -o+w -o -not -user vcf_sos -o -not -group vcf \')\' -type f -exec ls -ld {} \\;') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
    its('exit_status') { should cmp 0 }
  end
end
