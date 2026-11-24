control 'UBTU-24-300007' do
  title 'Ubuntu 24.04 LTS library files must be owned by root.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" are owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec stat -c "%n %U" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to be owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec chown root {} +)
  impact 0.5
  tag check_id: 'C-74730r1101755_chk'
  tag severity: 'medium'
  tag gid: 'V-270697'
  tag rid: 'SV-270697r1107308_rule'
  tag stig_id: 'UBTU-24-300007'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-74631r1107307_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  library_files = command("find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root").stdout.strip.split("\n").entries

  if library_files.any?
    library_files.each do |lib_file|
      describe file(lib_file) do
        its('owner') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are NOT owned by root' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
