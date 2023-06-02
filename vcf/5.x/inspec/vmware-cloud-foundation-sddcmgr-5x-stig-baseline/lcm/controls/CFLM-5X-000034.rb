control 'CFLM-5X-000034' do
  title 'The SDDC Manager LCM service must limit privileges to change the software resident within software libraries.'
  desc  'The application server should limit the ability of non-privileged users to modify any application libraries, scripts, or configuration files. The application files must be adequately protected with correct permissions as applied "out of the box".'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/vcf/lcm -xdev -type f -a '(' -perm -o+w -o -not -user vcf_lcm -o -not -group vcf ')' -exec ls -ld {} \\;

    If any files are returned in the output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chmod vcf_lcm:vcf <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag gid: 'V-CFLM-5X-000034'
  tag rid: 'SV-CFLM-5X-000034'
  tag stig_id: 'CFLM-5X-000034'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe command('find /opt/vmware/vcf/lcm -xdev -type f -a \'(\' -perm -o+w -o -not -user vcf_lcm -o -not -group vcf \')\' -exec ls -ld {} \\;') do
    its('stdout.strip') { should cmp '' }
  end
end
