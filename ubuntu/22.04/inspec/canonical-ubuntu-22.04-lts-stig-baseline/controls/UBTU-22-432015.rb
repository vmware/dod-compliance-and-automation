control 'UBTU-22-432015' do
  title 'Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For nonkernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries.

Ubuntu 22.04 LTS restricts access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify the sudo group has only members who require access to security functions by using the following command:

     $ grep sudo /etc/group
     sudo:x:27:<username>

If the sudo group contains users not needing access to security functions, this is a finding.'
  desc 'fix', 'Configure the sudo group with only members requiring access to security functions.

To remove a user from the sudo group, run:

     $ sudo gpasswd -d <username> sudo'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64288r953488_chk'
  tag severity: 'high'
  tag gid: 'V-260559'
  tag rid: 'SV-260559r958518_rule'
  tag stig_id: 'UBTU-22-432015'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-64196r953489_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  sudo_accounts = input('sudo_accounts')

  if sudo_accounts.count > 0
    sudo_accounts.each do |account|
      describe group('sudo') do
        its('members') { should include account }
      end
    end
  else
    describe.one do
      describe group('sudo') do
        its('members') { should be_nil }
      end
      describe group('sudo') do
        its('members') { should be_empty }
      end
    end
  end
end
