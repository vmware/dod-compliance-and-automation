control 'UBTU-22-232105' do
  title 'Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the "journalctl" command is group-owned by "root" by using the following command:

     $ sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \;
     /usr/bin/journalctl root

If "journalctl" is not group-owned by "root", this is a finding.'
  desc 'fix', 'Configure "journalctl" to be group-owned by "root":

     $ sudo chown :root /usr/bin/journalctl'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64235r953329_chk'
  tag severity: 'medium'
  tag gid: 'V-260506'
  tag rid: 'SV-260506r958566_rule'
  tag stig_id: 'UBTU-22-232105'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64143r953330_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/usr/bin/journalctl') do
    its('group') { should cmp 'root' }
  end
end
