control 'UBTU-22-232026' do
  title 'Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

The /var/log/btmp, /var/log/wtmp, and /var/log/lastlog files have group write and global read permissions to allow for the lastlog function to perform. Limiting the permissions beyond this configuration will result in the failure of functions that rely on the lastlog database.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS has all system log files under the "/var/log" directory with a permission set to "640" or less permissive by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

     $ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If the command displays any output, this is a finding.)
  desc 'fix', %q(Configure Ubuntu 22.04 LTS to set permissions of all log files under the "/var/log" directory to "640" or more restricted by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

     $ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;)
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64218r953278_chk'
  tag severity: 'medium'
  tag gid: 'V-260489'
  tag rid: 'SV-260489r958564_rule'
  tag stig_id: 'UBTU-22-232026'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-64126r953279_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  log_files = command('find /var/log -perm /137 ! -name "*[bw]tmp" ! -name "*lastlog" -type f -exec stat -c "%n %a" {} \;').stdout.strip.split("\n").entries

  describe 'Number of log files found with a permission NOT set to 640' do
    subject { log_files }
    its('count') { should eq 0 }
  end
end
