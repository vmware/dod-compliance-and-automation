control 'PHTN-40-000196' do
  title 'The Photon operating system must persist lockouts between system reboots.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

By default, account lockout information is stored under /var/run/faillock and is not persistent between reboots.'
  desc 'check', %q(At the command line, run the following command to verify account locking persists lockouts between system reboots

# grep '^dir' /etc/security/faillock.conf

Example result:

dir = /var/log/faillock

If the "dir" option is set to "/var/run/faillock", this is a finding.
If the "dir" option is not set to a persistent documented faillock directory, is missing or commented out, this is a finding.

Note: If faillock.conf is not used to configure pam_faillock.so, these options may be specified on the faillock lines in the system-auth and system-account files.)
  desc 'fix', 'Navigate to and open:

/etc/security/faillock.conf

Add or update the following lines:

dir = /var/log/faillock

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62602r1003648_chk'
  tag severity: 'medium'
  tag gid: 'V-258862'
  tag rid: 'SV-258862r1003649_rule'
  tag stig_id: 'PHTN-40-000196'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-62511r933646_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  if input('useFaillockConf')
    describe parse_config_file('/etc/security/faillock.conf') do
      its('dir') { should cmp '/var/log/faillock' }
    end
  else
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth').all_with_args('dir=/var/log/faillock') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail').all_with_args('dir=/var/log/faillock') }
    end
  end
end
