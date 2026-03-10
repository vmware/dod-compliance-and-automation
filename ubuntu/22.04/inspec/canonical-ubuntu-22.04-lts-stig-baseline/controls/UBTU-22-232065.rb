control 'UBTU-22-232065' do
  title 'Ubuntu 22.04 LTS library directories must be group-owned by "root".'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide library directories "/lib", "/lib64", and "/usr/lib" are group-owned by "root" by using the following command:

     $ sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;

If any systemwide shared library directory is returned, this is a finding.)
  desc 'fix', "Configure Ubuntu 22.04 LTS library directories to be protected from unauthorized access. Run the following command:

     $ sudo find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64227r953305_chk'
  tag severity: 'medium'
  tag gid: 'V-260498'
  tag rid: 'SV-260498r991560_rule'
  tag stig_id: 'UBTU-22-232065'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64135r953306_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_directories = command('find /lib /usr/lib /lib64 ! \-group root \-type d').stdout.strip.split("\n").entries

  if library_directories.count > 0
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
