control 'UBTU-22-232030' do
  title 'Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 22.04 LTS configures the "/var/log/syslog" file with mode "640" or less permissive by using the following command:

     $ stat -c "%n %a" /var/log/syslog
     /var/log/syslog 640

If a value of "640" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to have permissions of "640" for the "/var/log/syslog" file by using the following command:

     $ sudo chmod 0640 /var/log/syslog'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64220r953284_chk'
  tag severity: 'medium'
  tag gid: 'V-260491'
  tag rid: 'SV-260491r958566_rule'
  tag stig_id: 'UBTU-22-232030'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64128r953285_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    it { should_not be_more_permissive_than('0640') }
  end
end
