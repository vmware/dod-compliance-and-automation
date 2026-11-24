control 'UBTU-24-300010' do
  title 'Ubuntu 24.04 LTS library directories must be group-owned by root.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide library directories "/lib", "/lib64", and "/usr/lib" are group-owned by root with the following command:

$ sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;

If any systemwide shared library directory is returned, this is a finding.)
  desc 'fix', "Configure the system library directories to be protected from unauthorized access. Run the following command:

$ sudo find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \\;"
  impact 0.5
  tag check_id: 'C-74733r1066587_chk'
  tag severity: 'medium'
  tag gid: 'V-270700'
  tag rid: 'SV-270700r1066589_rule'
  tag stig_id: 'UBTU-24-300010'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-74634r1066588_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_directories = command('find /lib /usr/lib /lib64 ! \-group root \-type d').stdout.strip.split("\n").entries

  if library_directories.any?
    library_directories.each do |lib_file|
      describe file(lib_file) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system-wide shared library directories found that are NOT group-owned by root' do
      subject { library_directories }
      its('count') { should eq 0 }
    end
  end
end
