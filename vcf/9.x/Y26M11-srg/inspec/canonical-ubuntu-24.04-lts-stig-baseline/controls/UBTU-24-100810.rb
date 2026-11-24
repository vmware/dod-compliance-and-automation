control 'UBTU-24-100810' do
  title 'Ubuntu 24.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify the "sshd.service" is enabled and active with the following commands:

$ sudo systemctl is-enabled ssh
enabled

$ sudo systemctl is-active ssh
active

If "ssh.service" is not active or loaded, this is a finding.'
  desc 'fix', 'Enable the "ssh" service to start automatically on reboot with the following command:

$ sudo systemctl enable ssh.service

ensure the "ssh" service is running

$ sudo systemctl start ssh.service'
  impact 0.7
  tag check_id: 'C-74699r1066485_chk'
  tag severity: 'high'
  tag gid: 'V-270666'
  tag rid: 'SV-270666r1066487_rule'
  tag stig_id: 'UBTU-24-100810'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-74600r1066486_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (2)']

  describe systemd_service('sshd') do
    it { should be_enabled }
    it { should be_running }
  end
end
