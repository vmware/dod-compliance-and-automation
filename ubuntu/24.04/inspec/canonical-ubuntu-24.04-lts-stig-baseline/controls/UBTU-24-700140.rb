control 'UBTU-24-700140' do
  title 'Ubuntu 24.04 LTS must configure /var/log/syslog file to be owned by syslog.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 24.04 LTS configures the /var/log/syslog file to be owned by "syslog" with the following command:

$ stat -c "%n %U" /var/log/syslog
/var/log/syslog syslog

If the "/var/log/syslog" file is not owned by syslog, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have syslog own the /var/log/syslog file by running the following command:

$ sudo chown syslog /var/log/syslog'
  impact 0.5
  tag check_id: 'C-74802r1066794_chk'
  tag severity: 'medium'
  tag gid: 'V-270769'
  tag rid: 'SV-270769r1066796_rule'
  tag stig_id: 'UBTU-24-700140'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74703r1066795_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    its('owner') { should cmp 'syslog' }
  end
end
