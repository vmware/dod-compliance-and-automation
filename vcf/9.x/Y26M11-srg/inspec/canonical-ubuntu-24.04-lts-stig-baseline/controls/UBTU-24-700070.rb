control 'UBTU-24-700070' do
  title 'Ubuntu 24.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal files are group-owned by "systemd-journal" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \\;
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system.journal systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000@0005f97cd4a8c9b5-f088232c3718485a.journal~ systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cd2a1e0a7-d58b848af46813a4.journal~ systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cb900e501-55ea053b7f75ae1c.journal~ systemd-journal
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000.journal systemd-journal

If any output returned is not group-owned by "systemd-journal", this is a finding.'
  desc 'fix', 'Configure the system to set the appropriate group-ownership to the files used by the systemd journal.

Create a drop-in file if it does not already exist with the following command:

$ sudo vi /etc/tmpfiles.d/zzz-systemd-stig.conf

Add or modify the following lines in the "/usr/lib/tmpfiles.d/zzz-systemd-stig.conf" file:

Z /run/log/journal/%m ~0640 root systemd-journal - -
z /var/log/journal/%m 0640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Note: Restart the system for these settings to take effect.'
  impact 0.5
  tag check_id: 'C-74795r1066773_chk'
  tag severity: 'medium'
  tag gid: 'V-270762'
  tag rid: 'SV-270762r1184076_rule'
  tag stig_id: 'UBTU-24-700070'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74696r1184075_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  files = command('find /run/log/journal /var/log/journal -type f -exec stat -c "%n %G" {} \;').stdout.strip.split("\n").entries
  if files.any?
    files.each do |journal_file|
      path, = journal_file.split
      describe file(path) do
        its('group') { should cmp 'systemd-journal' }
      end
    end
  else
    describe 'Number of system journal files not group-owned by systemd-journal' do
      subject { files }
      its('count') { should eq 0 }
    end
  end
end
