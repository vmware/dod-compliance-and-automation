control 'PHTN-40-000199' do
  title 'The Photon operating system TDNF package management tool must cryptographically verify the authenticity of all software packages during installation for all repos.'
  desc 'Installation of any nontrusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc 'check', 'At the command line, run the following command to verify software packages are cryptographically verified during installation:

# grep gpgcheck /etc/yum.repos.d/*

If "gpgcheck" is not set to "1" in any returned file, this is a finding.'
  desc 'fix', 'Open the file where "gpgcheck" is not set to 1 with a text editor.

Add or update the following line:

gpgcheck=1'
  impact 0.7
  tag check_id: 'C-62604r933651_chk'
  tag severity: 'high'
  tag gid: 'V-258864'
  tag rid: 'SV-258864r933653_rule'
  tag stig_id: 'PHTN-40-000199'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-62513r933652_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  results = command('find /etc/yum.repos.d/ -type f').stdout
  if !results.empty?
    results.split.each do |repofile|
      describe file(repofile) do
        its('content') { should match /^(?=.*?\bgpgcheck=1\b).*$/ }
      end
    end
  else
    describe 'No YUM repo files found to check.' do
      skip 'No YUM repo files found to check.'
    end
  end
end
