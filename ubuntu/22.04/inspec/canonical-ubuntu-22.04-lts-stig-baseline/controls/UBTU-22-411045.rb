control 'UBTU-22-411045' do
  title 'Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', %q(Verify that Ubuntu 22.04 LTS utilizes the "pam_faillock" module by using the following command:

     $ grep faillock /etc/pam.d/common-auth

auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

If the "pam_faillock.so" module is not present in the "/etc/pam.d/common-auth" file, this is a finding.

Verify the "pam_faillock" module is configured to use the following options:

     $ sudo grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf
     audit
     silent
     deny = 3
     fail_interval = 900
     unlock_time = 0

If "audit" is commented out, or is missing, this is a finding.

If "silent" is commented out, or is missing, this is a finding.

If "deny" is set to a value greater than "3", is commented out, or is missing, this is a finding.

If "fail_interval" is set to a value greater than "900", is commented out, or is missing, this is a finding.

If "unlock_time" is not set to "0", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to utilize the "pam_faillock" module.

Add or modify the following lines in the "/etc/pam.d/common-auth" file, below the "auth" definition for "pam_unix.so":

auth     [default=die]  pam_faillock.so authfail
auth     sufficient          pam_faillock.so authsucc

Configure the "pam_faillock" module to use the following options.

Add or modify the following lines in the "/etc/security/faillock.conf" file:

audit
silent
deny = 3
fail_interval = 900
unlock_time = 0'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64278r953458_chk'
  tag severity: 'low'
  tag gid: 'V-260549'
  tag rid: 'SV-260549r958388_rule'
  tag stig_id: 'UBTU-22-411045'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-64186r953459_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']

  options = {
    assignment_regex: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/,
    multiple_values: false,
    key_values: 1,
    comment_char: '#'
  }
  describe file('/etc/pam.d/common-auth') do
    it { should exist }
  end

  describe command('grep faillock /etc/pam.d/common-auth') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*auth\s+sufficient\s+pam_faillock.so\s+authsucc($|\s+.*$)/ }
    its('stdout.strip') { should match /^\s*auth\s+\[default=die\]\s+pam_faillock.so\s+authfail($|\s+.*$)/ }
  end

  describe file('/etc/security/faillock.conf') do
    it { should exist }
  end

  describe parse_config_file('/etc/security/faillock.conf', options) do
    its('deny') { should_not eq nil }
    its('deny.to_i') { should be <= 3 }
    its('fail_interval') { should_not eq nil }
    its('fail_interval.to_i') { should be <= 990 }
    its('fail_interval') { should_not eq nil }
    its('unlock_time') { should eq '0' }
  end
  describe command('egrep \'silent|audit\' /etc/security/faillock.conf | grep -v \'#\'') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^audit($|\s+.*$)/ }
    its('stdout.strip') { should match /^silent($|\s+.*$)/ }
  end
end
