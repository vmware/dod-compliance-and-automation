control 'UBTU-22-232090' do
  title 'Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal files are owned by "root" by using the following command:

     $ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \;
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000003c7a-0006073f8d1c0fec.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-00000000000062a6-00060b4b414b617a.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000005301-000609a409
593.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/system@99dcc72bb1134aaeae4bf157aa7606f4-0000000000000001-000604dae53225ee.journal root
     /var/log/journal/3b018e681c904487b11671b9c1987cce/user-1000@bdedf14602ff4081a77dc7a6debc8626-000000000000083b-000604dae72c7e3b.journal root

If any output returned is not owned by "root", this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to set the appropriate ownership to the files used by the systemd journal:

Add or modify the following lines in the "/usr/lib/tmpfiles.d/systemd.conf" file:

Z /run/log/journal/%m ~2640 root systemd-journal - -
z /var/log/journal/%m 2640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Restart the system for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64232r953320_chk'
  tag severity: 'medium'
  tag gid: 'V-260503'
  tag rid: 'SV-260503r958566_rule'
  tag stig_id: 'UBTU-22-232090'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-64140r953321_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  files = command('find /run/log/journal /var/log/journal -type f -exec stat -c "%n %U" {} \;').stdout.strip.split("\n").entries
  if files.count > 0
    files.each do |journal_file|
      path, = journal_file.split
      describe file(path) do
        its('owner') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system journal files not owned by root' do
      subject { files }
      its('count') { should eq 0 }
    end
  end
end
