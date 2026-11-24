control 'UBTU-24-700120' do
  title 'Ubuntu 24.04 LTS must configure the /var/log directory to have mode "0755" or less permissive.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Note: If rsyslog is active and enabled on Ubuntu 24.04 LTS, this requirement is not applicable.

Verify Ubuntu 24.04 LTS configures the /var/log directory with a mode of "755" or less permissive with the following command:

$ stat -c "%n %a" /var/log
/var/log 755

If a value of "755" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have permissions of "0755" for the /var/log directory by running the following command:

$ sudo chmod 0755 /var/log'
  impact 0.5
  tag check_id: 'C-74800r1066788_chk'
  tag severity: 'medium'
  tag gid: 'V-270767'
  tag rid: 'SV-270767r1066790_rule'
  tag stig_id: 'UBTU-24-700120'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74701r1066789_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('mode') { should cmp <= 0o755 }
  end
end
