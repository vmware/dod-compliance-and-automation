control 'UBTU-22-255010' do
  title 'Ubuntu 22.04 LTS must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify the SSH package is installed by using the following command:

     $ sudo dpkg -l | grep openssh
     ii     openssh-client     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) client, for secure access to remote machines
     ii  openssh-server     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) server, for secure access from remote machines
     ii  openssh-sftp-server     1:8.9p1-3ubuntu0.4     amd64     secure shell (SSH) sftp server module, for SFTP access from remote machines

If the "openssh" server package is not installed, this is a finding.'
  desc 'fix', 'Install the "ssh" meta-package by using the following command:

     $ sudo apt install ssh'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64252r953380_chk'
  tag severity: 'high'
  tag gid: 'V-260523'
  tag rid: 'SV-260523r958908_rule'
  tag stig_id: 'UBTU-22-255010'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-64160r953381_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (2)']

  describe package('openssh-client') do
    it { should be_installed }
  end

  describe package('openssh-server') do
    it { should be_installed }
  end

  describe package('openssh-sftp-server') do
    it { should be_installed }
  end
end
