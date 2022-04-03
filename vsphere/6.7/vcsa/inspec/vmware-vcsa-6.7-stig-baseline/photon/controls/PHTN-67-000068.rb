control 'PHTN-67-000068' do
  title "The Photon operating system must use OpenSSH for remote maintenance
sessions."
  desc  "If the remote connection is not closed and verified as closed, the
session may remain open and be exploited by an attacker; this is referred to as
a zombie session. Remote connections must be disconnected and verified as
disconnected when nonlocal maintenance sessions have been terminated and are no
longer available for use.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # rpm -qa|grep openssh

    If there is no output, this is a finding.
  "
  desc 'fix', "Installing openssh manually is not supported by VMware. Revert
to a previous backup or redeploy the VCSA."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000395-GPOS-00175'
  tag satisfies: ['SRG-OS-000395-GPOS-00175', 'SRG-OS-000074-GPOS-00042',
'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058',
'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065',
'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-239139'
  tag rid: 'SV-239139r675225_rule'
  tag stig_id: 'PHTN-67-000068'
  tag fix_id: 'F-42309r675224_fix'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-000877', 'CCI-001941',
'CCI-001942', 'CCI-002420', 'CCI-002422', 'CCI-002891']
  tag nist: ['IA-5 (1) (c)', 'IA-7', 'MA-4 c', 'IA-2 (8)', 'IA-2 (9)', "SC-8
(2)", 'SC-8 (2)', 'MA-4 (7)']

  describe command('rpm -qa|grep openssh') do
    its('stdout') { should_not eq '' }
  end
end
