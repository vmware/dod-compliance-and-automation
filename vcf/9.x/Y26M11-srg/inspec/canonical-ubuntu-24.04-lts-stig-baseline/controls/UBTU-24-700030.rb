control 'UBTU-24-700030' do
  title 'Ubuntu 24.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages must be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the journalctl command has a permission set of "740" with the following command:

$ sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \\;
/usr/bin/journalctl 740

If journalctl is not set to "740", this is a finding'
  desc 'fix', 'Configure journalctl to have a permission set of "740":

$ sudo chmod 740 /usr/bin/journalctl'
  impact 0.5
  tag check_id: 'C-74791r1066761_chk'
  tag severity: 'medium'
  tag gid: 'V-270758'
  tag rid: 'SV-270758r1066763_rule'
  tag stig_id: 'UBTU-24-700030'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-74692r1066762_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe file('/usr/bin/journalctl') do
    its('mode') { should cmp '0740' }
  end
end
