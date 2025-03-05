control 'PHTN-40-000073' do
  title 'The Photon operating system /var/log directory must be restricted.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'At the command line, run the following command to verify permissions on the /var/log directory:

# stat -c "%n is owned by %U and group owned by %G with permissions of %a" /var/log

Expected result:

/var/log is owned by root and group owned by root with permissions of 755

If the /var/log directory is not owned by root, this is a finding.
If the /var/log directory is not group owned by root, this is a finding.
If the /var/log directory permissions are not set to 0755 or less, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# chown root:root /var/log
# chmod 0755 /var/log'
  impact 0.5
  tag check_id: 'C-62571r933552_chk'
  tag severity: 'medium'
  tag gid: 'V-258831'
  tag rid: 'SV-258831r958564_rule'
  tag stig_id: 'PHTN-40-000073'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-62480r933553_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe directory('/var/log') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
end
