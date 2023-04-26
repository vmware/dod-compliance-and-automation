control 'PHTN-40-000206' do
  title 'The Photon operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc  'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify the pam_faildelay.so module is used:

    # grep ^auth /etc/pam.d/system-auth

    Example result:

    auth required pam_faillock.so preauth
    auth required pam_unix.so
    auth required pam_faillock.so authfail
    auth optional pam_faildelay.so delay=4000000

    If the pam_faildelay.so module is not present with the delay set to at least 4 seconds, this is a finding.

    Note: The delay is configured in milliseconds.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-auth

    Add or update the following line:

    auth optional pam_faildelay.so delay=4000000
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-PHTN-40-000206'
  tag rid: 'SV-PHTN-40-000206'
  tag stig_id: 'PHTN-40-000206'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe pam('/etc/pam.d/system-auth') do
    its('lines') { should match_pam_rule('auth optional pam_faildelay.so') }
    its('lines') { should match_pam_rule('auth optional pam_faildelay.so').all_with_integer_arg('delay', '>=', 4000000) }
  end
end
