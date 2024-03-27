control 'PHTN-50-000194' do
  title 'The Photon operating system must audit logon attempts for unknown users.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify that audit logon attempts for unknown users is performed:

    # grep '^audit' /etc/security/faillock.conf

    Example result:

    audit

    If the \"audit\" option is not set, is missing or commented out, this is a finding.

    Note: If faillock.conf is not used to configure pam_faillock.so then these options may be specified on the faillock lines in the system-auth and system-account files.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/faillock.conf

    Add or update the following lines:

    audit
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag gid: 'V-PHTN-50-000194'
  tag rid: 'SV-PHTN-50-000194'
  tag stig_id: 'PHTN-50-000194'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  if input('useFaillockConf')
    describe parse_config_file('/etc/security/faillock.conf') do
      its('audit') { should_not be nil }
    end
  else
    describe pam('/etc/pam.d/system-auth') do
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so preauth').all_with_args('audit') }
      its('lines') { should match_pam_rule('auth required pam_faillock.so authfail').all_with_args('audit') }
    end
  end
end
