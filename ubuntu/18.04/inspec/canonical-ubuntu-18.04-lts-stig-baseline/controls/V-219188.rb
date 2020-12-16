# encoding: UTF-8

control 'V-219188' do
  title "The Ubuntu operating system must generate error messages that provide
information necessary for corrective actions without revealing information that
could be exploited by adversaries."
  desc  "Any operating system providing too much information in error messages
risks compromising the data and security of the structure, and content of error
messages needs to be carefully considered by the organization.

    Organizations carefully consider the structure/content of error messages.
The extent to which information systems are able to identify and handle error
conditions is guided by organizational policy and operational requirements.
Information that could be exploited by adversaries includes, for example,
erroneous logon attempts with passwords entered by mistake as the username,
mission/business information that can be derived from (if not stated explicitly
by) information recorded, and personal information, such as account numbers,
social security numbers, and credit card numbers.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system has all system log files under the
/var/log directory with a permission set to 640, by using the following command:

    # sudo find /var/log -perm /137 -type f -exec stat -c \"%n %a\" {} \\;

    If command displays any output, this is a finding.
  "
  desc  'fix', "
    Configured the Ubuntu operating system to set permissions of all log files
under /var/log directory to 640 or more restricted, by using the following
command:

    # sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \\;
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag gid: 'V-219188'
  tag rid: 'SV-219188r508662_rule'
  tag stig_id: 'UBTU-18-010121'
  tag fix_id: 'F-20912r304893_fix'
  tag cci: ['V-100603', 'SV-109707', 'CCI-001312']
  tag nist: ['SI-11 a']

  log_files = command('find /var/log -perm /137 -type f -exec stat -c "%n %a" {} \;').stdout.strip.split("\n").entries

  describe "Number of log files found with a permission NOT set to 640" do
    subject { log_files }
    its("count") { should eq 0 }
  end
end

