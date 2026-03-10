control 'UBTU-22-232125' do
  title 'Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 22.04 LTS configures the "/var/log" directory to be group-owned by "syslog" by using the following command:

     $ stat -c "%n %G" /var/log
     /var/log syslog

If the "/var/log" directory is not group-owned by "syslog", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to have syslog group-own the "/var/log" directory by using the following command:

     $ sudo chgrp syslog /var/log'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64238r953338_chk'
  tag severity: 'medium'
  tag gid: 'V-260509'
  tag rid: 'SV-260509r958566_rule'
  tag stig_id: 'UBTU-22-232125'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64146r953339_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('group') { should cmp 'syslog' }
  end
end
