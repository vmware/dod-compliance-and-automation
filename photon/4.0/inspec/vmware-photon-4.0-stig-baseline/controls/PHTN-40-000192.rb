control 'PHTN-40-000192' do
  title 'The Photon operating system must be configured to use the pam_faillock.so module.'
  desc  "
    By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

    This module maintains a list of failed authentication attempts per user during a specified interval and locks the account in case there were more than deny consecutive failed authentications.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify the pam_faillock.so module is used:

    # grep ^auth /etc/pam.d/system-auth

    Example result:

    auth required pam_faillock.so preauth
    auth required pam_unix.so
    auth required pam_faillock.so authfail

    If the pam_faillock.so module is not present with the \"preauth\" line listed before pam_unix.so, this is a finding.
    If the pam_faillock.so module is not present with the \"authfail\" line listed after pam_unix.so, this is a finding.

    # grep ^account /etc/pam.d/system-account

    Example result:

    account required pam_faillock.so
    account required pam_unix.so

    If the pam_faillock.so module is not present and listed before pam_unix.so, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-auth

    Add or update the following lines making sure to place the preauth line before the pam_unix.so module:

    auth required pam_faillock.so preauth
    auth required pam_faillock.so authfail

    Navigate to and open:

    /etc/pam.d/system-account

    Add or update the following lines making sure to place the line before the pam_unix.so module:

    account required pam_faillock.so

    Note: The lines shown assume the /etc/security/faillock.conf file is used to configure pam_faillock.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag gid: 'V-PHTN-40-000192'
  tag rid: 'SV-PHTN-40-000192'
  tag stig_id: 'PHTN-40-000192'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe pam('/etc/pam.d/system-auth') do
    its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
    its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
  end
  describe pam('/etc/pam.d/system-account') do
    its('lines') { should match_pam_rule('account required pam_faillock.so') }
  end
end
