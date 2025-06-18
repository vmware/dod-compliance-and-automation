control 'UBTU-22-255015' do
  title 'Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify the "ssh.service" is enabled and active by using the following commands:

     $ sudo systemctl is-enabled ssh
     enabled

     $ sudo systemctl is-active ssh
     active

If "ssh.service" is not enabled and active, this is a finding.'
  desc 'fix', 'Enable and start the "ssh.service" by using the following command:

     $ sudo systemctl enable ssh.service --now'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64253r953383_chk'
  tag severity: 'high'
  tag gid: 'V-260524'
  tag rid: 'SV-260524r958908_rule'
  tag stig_id: 'UBTU-22-255015'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-64161r953384_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (2)']

  describe systemd_service('sshd') do
    it { should be_enabled }
    it { should be_running }
  end
end
