control 'CFCS-4X-000007' do
  title 'The SDDC Manager Common Services service must only use the authorized libraries.'
  desc  'Common Services ships with a number of libraries out of the box. Any additional libraries may affect the availability and integrity of the system and must be approved and documented by the ISSO before deployment.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # diff <(find /opt/vmware/vcf/commonsvcs/lib -type f|sort) <(rpm -ql vcf-commonsvcs|grep \"/opt/vmware/vcf/commonsvcs/lib/\"|sort)

    If there is any output, this indicates a library file that the server did not ship with originally.

    If this file is not known and approved, this is a finding.
  "
  desc  'fix', "
    For every unauthorized file returned by the check, run the following command:

    # rm <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFCS-4X-000007'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('diff <(find /opt/vmware/vcf/commonsvcs/lib -type f|sort) <(rpm -ql vcf-commonsvcs|grep "/opt/vmware/vcf/commonsvcs/lib/"|sort)') do
    its('stdout.strip') { should cmp '' }
  end
end
