control 'UBTU-22-232020' do
  title 'Ubuntu 22.04 LTS library files must have mode "755" or less permissive.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" have mode "755" or less permissive by using the following command:

     $ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \;

If any files are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the library files to be protected from unauthorized access. Run the following command:

     $ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64216r953272_chk'
  tag severity: 'medium'
  tag gid: 'V-260487'
  tag rid: 'SV-260487r991560_rule'
  tag stig_id: 'UBTU-22-232020'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64124r953273_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_files = command('find /lib /lib64 /usr/lib -perm /022 -type f').stdout.strip.split("\n").entries

  if library_files.count > 0
    library_files.each do |lib_file|
      describe file(lib_file) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are less permissive than 0755' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
