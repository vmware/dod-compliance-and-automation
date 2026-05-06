control 'UBTU-22-232075' do
  title 'Ubuntu 22.04 LTS library files must be group-owned by "root".'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" are group owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec stat -c "%n %G" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to be group owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec chown :root {} +)
  impact 0.5
  tag check_id: 'C-64229r1101710_chk'
  tag severity: 'medium'
  tag gid: 'V-260500'
  tag rid: 'SV-260500r1107266_rule'
  tag stig_id: 'UBTU-22-232075'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-64137r1107265_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_files = command("find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root").stdout.strip.split("\n").entries

  if library_files.any?
    library_files.each do |lib_file|
      describe file(lib_file) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are NOT group-owned by root' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
