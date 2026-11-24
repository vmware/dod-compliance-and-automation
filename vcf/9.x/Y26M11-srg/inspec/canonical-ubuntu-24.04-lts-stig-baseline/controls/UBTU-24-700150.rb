control 'UBTU-24-700150' do
  title 'Ubuntu 24.04 LTS must configure /var/log/syslog file with mode "0640" or less permissive.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that Ubuntu 24.04 LTS configures the /var/log/syslog file with mode "0640" or less permissive with the following command:

$ stat -c "%n %a" /var/log/syslog
/var/log/syslog 640

If a value of "640" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have permissions of "0640" for the /var/log/syslog file by running the following command:

$ sudo chmod 0640 /var/log/syslog'
  impact 0.5
  tag check_id: 'C-74803r1066797_chk'
  tag severity: 'medium'
  tag gid: 'V-270770'
  tag rid: 'SV-270770r1066799_rule'
  tag stig_id: 'UBTU-24-700150'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74704r1066798_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    its('mode') { should cmp <= 0o640 }
  end
end
