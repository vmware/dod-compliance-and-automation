control 'UBTU-22-232095' do
  title 'Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal files are group-owned by "systemd-journal" by using the following command:

     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \;
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000005301-000609a409
593.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000000001-000604dae53225ee.journal systemd-journal
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-000000000000083b-000604dae72c7e3b.journal systemd-journal

If any output returned is not group-owned by "systemd-journal", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to set the appropriate group-ownership to the files used by the systemd journal:

Add or modify the following line in the "/usr/lib/tmpfiles.d/systemd.conf" file:

Z /run/log/journal/%m ~2640 root systemd-journal - -
z /var/log/journal/%m 2640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Restart the system for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64233r953323_chk'
  tag severity: 'medium'
  tag gid: 'V-260504'
  tag rid: 'SV-260504r958566_rule'
  tag stig_id: 'UBTU-22-232095'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64141r953324_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  files = command('find /run/log/journal /var/log/journal -type f -exec stat -c "%n %G" {} \;').stdout.strip.split("\n").entries
  if files.count > 0
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
