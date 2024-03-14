control 'CFLM-4X-000010' do
  title 'The SDDC Manager LCM service directory tree must have permissions in an "out of the box" state.'
  desc  'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. The application files must be adequately protected with correct permissions as applied "out of the box".'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/vcf/lcm -xdev -type f -a '(' -perm -o+w -o -not -user vcf_lcm -o -not -group vcf ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # chmod o-w <file>
    # chmod vcf-lcm:vcf <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000380-WSR-000072']
  tag gid: 'V-CFLM-4X-000010'
  tag rid: 'SV-CFLM-4X-000010'
  tag stig_id: 'CFLM-4X-000010'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['CM-5 (1)', 'SC-2']

  describe command('find /opt/vmware/vcf/lcm -xdev -type f -a \'(\' -perm -o+w -o -not -user vcf_lcm -o -not -group vcf \')\' -exec ls -ld {} \\;') do
    its('stdout.strip') { should eq '' }
  end
end
