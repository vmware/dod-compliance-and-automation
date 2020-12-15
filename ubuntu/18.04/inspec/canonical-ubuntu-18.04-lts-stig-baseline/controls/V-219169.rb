# encoding: UTF-8

control 'V-219169' do
  title "The Ubuntu operating system must be configured so that only users who
need access to security functions are part of the sudo group."
  desc  "An isolation boundary provides access control and protects the
integrity of the hardware, software, and firmware that perform security
functions.

    Security functions are the hardware, software, and/or firmware of the
information system responsible for enforcing the system security policy and
supporting the isolation of code and data on which the protection is based.
Operating systems implement code separation (i.e., separation of security
functions from nonsecurity functions) in a number of ways, including through
the provision of security kernels via processor rings or processor modes. For
non-kernel code, security function isolation is often achieved through file
system protections that serve to protect the code on disk and address space
protections that protect executing code.

    Developers and implementers can increase the assurance in security
functions by employing well-defined security policy models; structured,
disciplined, and rigorous hardware and software development techniques; and
sound system/security engineering principles. Implementation may include
isolation of memory space and libraries.

    The Ubuntu operating system restricts access to security functions through
the use of access control mechanisms and by implementing least privilege
capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the sudo group has only members who should have access to
security functions.

    # grep sudo /etc/group

    sudo:x:27:foo

    If the sudo group contains users not needing access to security functions,
this is a finding.
  "
  desc  'fix', "
    Configure the sudo group with only members requiring access to security
functions.

    To remove a user from the sudo group run:

    sudo gpasswd -d <username> sudo
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-219169'
  tag rid: 'SV-219169r508662_rule'
  tag stig_id: 'UBTU-18-010037'
  tag fix_id: 'F-20893r304836_fix'
  tag cci: ['V-100565', 'SV-109669', 'CCI-001084']
  tag nist: ['SC-3']

  sudo_accounts = input('sudo_accounts')

  if sudo_accounts.count > 0
    sudo_accounts.each do |account|
      describe group('sudo') do
        its('members') { should include account }
      end
    end
  else
    describe "No accounts exist in sudo group" do
      describe group('sudo') do
        its('members') { should be_empty }
      end
    end
  end
  
end

