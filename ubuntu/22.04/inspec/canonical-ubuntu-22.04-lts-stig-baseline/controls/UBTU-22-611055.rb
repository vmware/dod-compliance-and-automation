control 'UBTU-22-611055' do
  title 'Ubuntu 22.04 LTS must store only encrypted representations of passwords.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the Ubuntu operating stores only encrypted representations of passwords with the following command:

     $ grep pam_unix.so /etc/pam.d/common-password
     password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=100000

If "sha512" is missing from the "pam_unix.so" line, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to store encrypted representations of passwords.

Add or modify the following line in the "/etc/pam.d/common-password" file:

password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=100000'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64298r1044765_chk'
  tag severity: 'medium'
  tag gid: 'V-260569'
  tag rid: 'SV-260569r1044767_rule'
  tag stig_id: 'UBTU-22-611055'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-64206r1044766_fix'
  tag 'documentable'
  tag cci: ['CCI-004062', 'CCI-000196']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (c)']

  password_list = command('grep pam_unix.so /etc/pam.d/common-password').stdout.split("\n")

  describe file('/etc/pam.d/common-password') do
    it { should exist }
  end

  password_list.each do |password|
    describe.one do
      describe password do
        it { should include 'sha512' }
      end
      describe password do
        it { should include 'yescrypt' }
      end
    end
  end
end
