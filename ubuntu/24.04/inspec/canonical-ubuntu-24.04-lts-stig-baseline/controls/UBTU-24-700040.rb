control 'UBTU-24-700040' do
  title 'Ubuntu 24.04 LTS must be configured so that the "journalctl" command is owned by "root".'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the journalctl command is owned by "root" with the following command:

$ sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \\;
/usr/bin/journalctl root

If journalctl is not owned by "root", this is a finding.'
  desc 'fix', 'Configure journalctl to be owned by "root":

$ sudo chown root /usr/bin/journalctl'
  impact 0.5
  tag check_id: 'C-74792r1068366_chk'
  tag severity: 'medium'
  tag gid: 'V-270759'
  tag rid: 'SV-270759r1068367_rule'
  tag stig_id: 'UBTU-24-700040'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74693r1066765_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/usr/bin/journalctl') do
    its('owner') { should cmp 'root' }
  end
end
