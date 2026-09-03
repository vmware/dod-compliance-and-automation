control 'PHTN-50-000108' do
  title 'The Photon operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify accounts are locked until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made:

    # grep '^unlock_time =' /etc/security/faillock.conf

    Example result:

    unlock_time = 0

    If the \"unlock_time\" option is not set to \"0\", is missing or commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/faillock.conf

    Add or update the following lines:

    unlock_time = 0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag gid: 'V-PHTN-50-000108'
  tag rid: 'SV-PHTN-50-000108'
  tag stig_id: 'PHTN-50-000108'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  if input('useFaillockConf')
    describe parse_config_file('/etc/security/faillock.conf') do
      its('unlock_time') { should cmp 0 }
    end
  else
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth').all_with_integer_arg('unlock_time', '==', 0) }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail').all_with_integer_arg('unlock_time', '==', 0) }
    end
  end
end
