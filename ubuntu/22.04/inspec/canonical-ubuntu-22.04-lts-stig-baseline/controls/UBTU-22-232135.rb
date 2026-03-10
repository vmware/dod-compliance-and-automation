control 'UBTU-22-232135' do
  title 'Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 22.04 LTS configures the "/var/log/syslog" file to be group-owned by "adm" by using the following command:

     $ stat -c "%n %G" /var/log/syslog
     /var/log/syslog adm

If the "/var/log/syslog" file is not group-owned by "adm", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to have adm group-own the "/var/log/syslog" file by using the following command:

     $ sudo chgrp adm /var/log/syslog'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64240r953344_chk'
  tag severity: 'medium'
  tag gid: 'V-260511'
  tag rid: 'SV-260511r958566_rule'
  tag stig_id: 'UBTU-22-232135'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64148r953345_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    its('group') { should cmp 'adm' }
  end
end
