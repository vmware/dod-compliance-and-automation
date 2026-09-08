control 'PHTN-50-000199' do
  title 'The Photon operating system TDNF package management tool must cryptographically verify the authenticity of all software packages during installation for all repos.'
  desc  'Installation of any nontrusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify software packages are cryptographically verified during installation:

    # grep gpgcheck /etc/yum.repos.d/*

    If \"gpgcheck\" is not set to \"1\" in any returned file, this is a finding.
  "
  desc 'fix', "
    Open the file where \"gpgcheck\" is not set to 1 with a text editor.

    Add or update the following line:

    gpgcheck=1
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-PHTN-50-000199'
  tag rid: 'SV-PHTN-50-000199'
  tag stig_id: 'PHTN-50-000199'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']

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
