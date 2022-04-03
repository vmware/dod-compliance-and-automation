control 'PHTN-67-000062' do
  title "The Photon operating system RPM package management tool must
cryptographically verify the authenticity of all software packages during
installation."
  desc  "Installation of any non-trusted software, patches, service packs,
device drivers, or operating system components can significantly affect the
overall security of the operating system. Ensuring all packages' cryptographic
signatures are valid prior to installation ensures the provenance of the
software and protects against malicious tampering."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc

    If the command returns any output, this is a finding.
  "
  desc 'fix', "Open the file containing \"nosignature\" with a text editor and
remove the option."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-239133'
  tag rid: 'SV-239133r675207_rule'
  tag stig_id: 'PHTN-67-000062'
  tag fix_id: 'F-42303r675206_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc') do
    its('stdout') { should eq '' }
  end
end
