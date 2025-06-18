control 'UBTU-22-232025' do
  title 'Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log" directory has mode of "755" or less permissive by using the following command:

Note: If rsyslog is active and enabled on the operating system, this requirement is not applicable.

     $ stat -c "%n %a" /var/log
     /var/log 755

If a value of "755" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure the "/var/log" directory to have permissions of "0755" by using the following command:

     $ sudo chmod 0755 /var/log'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64217r953275_chk'
  tag severity: 'medium'
  tag gid: 'V-260488'
  tag rid: 'SV-260488r958566_rule'
  tag stig_id: 'UBTU-22-232025'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64125r953276_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    it { should_not be_more_permissive_than('0755') }
  end
end
