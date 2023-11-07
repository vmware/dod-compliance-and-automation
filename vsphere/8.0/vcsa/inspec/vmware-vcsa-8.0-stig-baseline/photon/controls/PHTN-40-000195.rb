control 'PHTN-40-000195' do
  title 'The Photon operating system must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

Unless specified the root account is not included in the default faillock module options and should be included.'
  desc 'check', %q(At the command line, run the following command to verify accounts are locked after three consecutive invalid logon attempts by a user during a 15-minute time period includes the root account:

# grep '^even_deny_root' /etc/security/faillock.conf

Example result:

even_deny_root

If the "even_deny_root" option is not set, is missing or commented out, this is a finding.

Note: If faillock.conf is not used to configure pam_faillock.so then these options may be specified on the faillock lines in the system-auth and system-account files.)
  desc 'fix', 'Navigate to and open:

/etc/security/faillock.conf

Add or update the following lines:

even_deny_root

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62601r933642_chk'
  tag severity: 'medium'
  tag gid: 'V-258861'
  tag rid: 'SV-258861r933644_rule'
  tag stig_id: 'PHTN-40-000195'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-62510r933643_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  if input('useFaillockConf')
    describe parse_config_file('/etc/security/faillock.conf') do
      its('even_deny_root') { should_not be nil }
    end
  else
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth').all_with_args('even_deny_root') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail').all_with_args('even_deny_root') }
    end
  end
end
