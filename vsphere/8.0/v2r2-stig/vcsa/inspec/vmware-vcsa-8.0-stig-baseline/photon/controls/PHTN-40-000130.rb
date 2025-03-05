control 'PHTN-40-000130' do
  title 'The Photon operating system TDNF package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc 'Installation of any nontrusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc 'check', %q(At the command line, run the following command to verify software packages are cryptographically verified during installation:

# grep '^gpgcheck' /etc/tdnf/tdnf.conf

Example result:

gpgcheck=1

If "gpgcheck" is not set to "true", "1", or "yes", this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/tdnf/tdnf.conf

Add or update the following line:

gpgcheck=1'
  impact 0.7
  tag check_id: 'C-62586r933597_chk'
  tag severity: 'high'
  tag gid: 'V-258846'
  tag rid: 'SV-258846r1003646_rule'
  tag stig_id: 'PHTN-40-000130'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-62495r933598_fix'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']

  # This config file has a [main] section header at the top
  describe.one do
    describe parse_config_file('/etc/tdnf/tdnf.conf').params['main'] do
      its('gpgcheck') { should cmp 1 }
    end
    describe parse_config_file('/etc/tdnf/tdnf.conf').params['main'] do
      its('gpgcheck') { should cmp 'true' }
    end
    describe parse_config_file('/etc/tdnf/tdnf.conf').params['main'] do
      its('gpgcheck') { should cmp 'yes' }
    end
  end
end
