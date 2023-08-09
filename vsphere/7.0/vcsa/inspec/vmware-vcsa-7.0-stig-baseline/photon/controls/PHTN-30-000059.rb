control 'PHTN-30-000059' do
  title 'The Photon operating system RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc "Installation of any nontrusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering."
  desc 'check', 'At the command line, run the following command:

# grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc

If the command returns any output, this is a finding.'
  desc 'fix', 'Open the file containing "nosignature" with a text editor and remove the option.'
  impact 0.5
  tag check_id: 'C-60205r887262_chk'
  tag severity: 'medium'
  tag gid: 'V-256530'
  tag rid: 'SV-256530r887264_rule'
  tag stig_id: 'PHTN-30-000059'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60148r887263_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc') do
    its('stdout') { should eq '' }
  end
end
