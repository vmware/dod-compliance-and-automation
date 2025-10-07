control 'PHTN-50-000206' do
  title 'The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc  'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the pam_faildelay.so module is used:

    # grep '^auth' /etc/pam.d/system-auth

    Example result:

    auth required pam_faillock.so preauth
    auth sufficient pam_unix.so
    auth required pam_faillock.so authfail
    auth optional pam_faildelay.so delay=4000000
    auth required pam_deny.so

    If the pam_faildelay.so module is not present with the delay set to at least four seconds, this is a finding.

    Note: The delay is configured in microseconds.
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
  tag gid: 'V-PHTN-50-000206'
  tag rid: 'SV-PHTN-50-000206'
  tag stig_id: 'PHTN-50-000206'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-auth') do
    its('content') { should match(/^auth\s+(required|requisite|optional)\s+pam_faildelay\.so\s+(?=.*\bdelay=4000000\b).*$/) }
  end
end
