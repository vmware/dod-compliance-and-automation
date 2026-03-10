control 'PHTN-30-000061' do
  title 'The Photon operating system YUM repository must cryptographically verify the authenticity of all software packages during installation.'
  desc 'Installation of any nontrusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. Cryptographically verifying the authenticity of all software packages during installation ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc 'check', 'At the command line, run the following command:

# grep gpgcheck /etc/yum.repos.d/*

If "gpgcheck" is not set to "1" in any returned file, this is a finding.'
  desc 'fix', 'Open the file where "gpgcheck" is not set to "1" with a text editor.

Remove any existing "gpgcheck" setting and add the following line at the end of the file:

gpgcheck=1'
  impact 0.5
  tag check_id: 'C-60207r887268_chk'
  tag severity: 'medium'
  tag gid: 'V-256532'
  tag rid: 'SV-256532r887270_rule'
  tag stig_id: 'PHTN-30-000061'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60150r887269_fix'
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
