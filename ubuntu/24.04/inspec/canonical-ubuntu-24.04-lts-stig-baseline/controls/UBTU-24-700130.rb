control 'UBTU-24-700130' do
  title 'Ubuntu 24.04 LTS must configure the /var/log/syslog file to be group-owned by adm.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 24.04 LTS configures the /var/log/syslog file to be group-owned by "adm" with the following command:

$ stat -c "%n %G" /var/log/syslog
/var/log/syslog adm

If the /var/log/syslog file is not group-owned by "adm", this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have adm group-own the /var/log/syslog file by running the following command:

$ sudo chgrp adm /var/log/syslog'
  impact 0.5
  tag check_id: 'C-74801r1066791_chk'
  tag severity: 'medium'
  tag gid: 'V-270768'
  tag rid: 'SV-270768r1066793_rule'
  tag stig_id: 'UBTU-24-700130'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74702r1066792_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    its('group') { should cmp 'adm' }
  end
end
