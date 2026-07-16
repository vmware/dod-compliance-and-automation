control 'UBTU-24-700080' do
  title 'Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root".'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories are owned by "root" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \\;
/run/log/journal root
/var/log/journal root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e root

If any output returned is not owned by "root", this is a finding.'
  desc 'fix', 'Configure the system to set the appropriate ownership to the directories used by the systemd journal.

Create a drop-in file if it does not already exist with the following command:

$ sudo vi /etc/tmpfiles.d/zzz-systemd-stig.conf

Add or modify the following lines in the "/usr/lib/tmpfiles.d/zzz-systemd-stig.conf" file:

z /run/log/journal 0640 root systemd-journal - -
z /var/log/journal 0640 root systemd-journal - -

Note: Restart the system for these settings to take effect.'
  impact 0.5
  tag check_id: 'C-74796r1066776_chk'
  tag severity: 'medium'
  tag gid: 'V-270763'
  tag rid: 'SV-270763r1184078_rule'
  tag stig_id: 'UBTU-24-700080'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74697r1184077_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  directories = command('find /run/log/journal /var/log/journal -type d -exec stat -c "%n %U" {} \;').stdout.strip.split("\n").entries
  if directories.any?
    directories.each do |journal_dir|
      path, = journal_dir.split
      describe file(path) do
        its('owner') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system journal directories not owned by root' do
      subject { directories }
      its('count') { should eq 0 }
    end
  end
end
