control 'UBTU-22-232027' do
  title 'Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories have permissions set to "2750" or less permissive by using the following command:

$ sudo find /run/log/journal /var/log/journal -type d -exec stat -c "%n %a" {} \\;
/run/log/journal 2750
/var/log/journal 2750
/var/log/journal/3b018e681c904487b11671b9c1987cce 2750

If any output returned has a permission set greater than "2750", this is a finding.

Verify all files in the /run/log/journal and /var/log/journal directories have permissions set to "640" or less permissive by using the following command:

     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \\;
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal 640
     /var/log/journal/3b018e681c904487b11671b9c1987cce

If any output returned has a permission set greater than "640", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to set the appropriate permissions to the files and directories used by the systemd journal:

Add or modify the following lines in the "`/usr/lib/tmpfiles.d/systemd.conf" file:
z /run/log/journal 2750 root systemd-journal - -
Z /run/log/journal/%m ~2750 root systemd-journal - -
z /var/log/journal 2750 root systemd-journal - -
z /var/log/journal/%m 2750 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Restart the system for the changes to take effect.'
  impact 0.5
  tag check_id: 'C-64219r1014779_chk'
  tag severity: 'medium'
  tag gid: 'V-260490'
  tag rid: 'SV-260490r1069105_rule'
  tag stig_id: 'UBTU-22-232027'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-64127r1069104_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  directories = command('find /run/log/journal /var/log/journal -type d').stdout.strip.split("\n").entries
  if !directories.empty?
    directories.each do |journal_dir|
      result = command("stat -c '%a' #{journal_dir}").stdout.chomp
      describe "The directory: #{journal_dir} permissions" do
        subject { result }
        it { should cmp '2750' }
      end
    end
  else
    describe 'No journal directories found.' do
      subject { directories }
      it { should_not be_empty }
    end
  end

  files = command('find /run/log/journal /var/log/journal -type f').stdout.strip.split("\n").entries
  if !files.empty?
    files.each do |journal_file|
      describe file(journal_file) do
        it { should_not be_more_permissive_than('640') }
      end
    end
  else
    describe 'No journal files found.' do
      subject { files }
      it { should_not be_empty }
    end
  end
end
