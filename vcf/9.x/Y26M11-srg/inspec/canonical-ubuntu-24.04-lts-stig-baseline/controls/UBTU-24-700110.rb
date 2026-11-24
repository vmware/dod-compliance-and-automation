control 'UBTU-24-700110' do
  title 'Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root.'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify Ubuntu 24.04 LTS configures the /var/log directory to be owned by "root" with the following command:

$ stat -c "%n %U" /var/log
/var/log root

If the "/var/log" directory is not owned by root, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to have root own the /var/log directory by running the following command:

$ sudo chown root /var/log'
  impact 0.5
  tag check_id: 'C-74799r1066785_chk'
  tag severity: 'medium'
  tag gid: 'V-270766'
  tag rid: 'SV-270766r1066787_rule'
  tag stig_id: 'UBTU-24-700110'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74700r1066786_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('owner') { should cmp 'root' }
  end
end
