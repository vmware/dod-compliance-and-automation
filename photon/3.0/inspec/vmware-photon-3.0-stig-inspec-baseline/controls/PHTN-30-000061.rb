control 'PHTN-30-000061' do
  title 'The Photon operating system RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc  'Installation of any non-trusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor. '
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep gpgcheck /etc/yum.repos.d/*

    If \"gpgcheck\" is not set to \"1\" in any returned file, this is a finding.
  "
  desc 'fix', "
    Open the file where \"gpgcheck\" is not set to 1 with a text editor.

    Remove any existing \"gpgcheck\" setting and add the following line at the end of the file:

    gpgcheck=1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000061'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  command('find /etc/yum.repos.d/ -type f').stdout.split.each do |repofile|
    describe file(repofile) do
      its('content') { should match /^(?=.*?\bgpgcheck=1\b).*$/ }
    end
  end
end
