control 'UBTU-24-200610' do
  title 'Ubuntu 24.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', %q(Verify that Ubuntu 24.04 LTS utilizes the "pam_faillock" module with the following command:

$ grep faillock /etc/pam.d/common-auth
auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

If the pam_faillock.so module is not present in the "/etc/pam.d/common-auth" file, this is a finding.

Verify the pam_faillock module is configured to use the following options:

$ sudo egrep 'silent|audit|deny|fail_interval| unlock_time' /etc/security/faillock.conf
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0

If the "silent" keyword is missing or commented out, this is a finding.
If the "audit" keyword is missing or commented out, this is a finding.
If the "deny" keyword is missing, commented out, or set to a value greater than "3", this is a finding.
If the "fail_interval" keyword is missing, commented out, or set to a value greater than "900", this is a finding.
If the "unlock_time" keyword is missing, commented out, or not set to "0", this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to utilize the "pam_faillock" module.

Edit the /etc/pam.d/common-auth file to add the following lines below the "auth" definition for pam_unix.so:
auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

Configure the "pam_faillock" module to use the following options:

Edit the /etc/security/faillock.conf file and add/update the following keywords and values:
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0'
  impact 0.3
  tag check_id: 'C-74723r1067125_chk'
  tag severity: 'low'
  tag gid: 'V-270690'
  tag rid: 'SV-270690r1067126_rule'
  tag stig_id: 'UBTU-24-200610'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-74624r1066558_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']

  common_auth_file = input('common_auth_file')
  faillock_file = input('faillock_file')

  options = {
    assignment_regex: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/,
    multiple_values: false,
    key_values: 1,
    comment_char: '#'
  }
  describe file(common_auth_file) do
    it { should exist }
  end

  describe command("grep faillock #{common_auth_file}") do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match(/^\s*auth\s+sufficient\s+pam_faillock.so\s+authsucc($|\s+.*$)/) }
    its('stdout.strip') { should match(/^\s*auth\s+\[default=die\]\s+pam_faillock.so\s+authfail($|\s+.*$)/) }
  end

  describe file(common_auth_file) do
    it 'has pam_faillock.so entries after pam_unix.so' do
      content = subject.content

      unix_pos = content.index('pam_unix.so')
      authsucc_pos = content.index('pam_faillock.so authsucc')
      authfail_pos = content.index('pam_faillock.so authfail')

      expect(unix_pos).not_to be_nil
      expect(authsucc_pos).not_to be_nil
      expect(authfail_pos).not_to be_nil

      expect(authsucc_pos).to be > unix_pos
      expect(authfail_pos).to be > unix_pos
    end
  end

  describe file(faillock_file) do
    it { should exist }
  end

  describe command("egrep 'silent|audit' #{faillock_file} | grep -v '#'") do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match(/^audit($|\s+.*$)/) }
    its('stdout.strip') { should match(/^silent($|\s+.*$)/) }
  end

  describe parse_config_file(faillock_file, options) do
    its('deny') { should_not eq nil }
    its('deny.to_i') { should be <= 3 }
    its('fail_interval') { should_not eq nil }
    its('fail_interval.to_i') { should be <= 990 }
    its('fail_interval') { should_not eq nil }
    its('unlock_time') { should eq '0' }
  end
end
