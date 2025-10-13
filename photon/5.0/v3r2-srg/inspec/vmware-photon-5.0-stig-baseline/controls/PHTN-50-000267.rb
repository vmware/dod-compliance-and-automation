control 'PHTN-50-000267' do
  title 'The Photon operating system must be configured to use the pam_deny.so module.'
  desc  'By requiring the use of the pam_deny.so module, any authentication attempt that does not explicitly succeed with a previous PAM module will be denied. This ensures that no unhandled or ambiguous authentication paths allow unintended access, thereby enforcing a fail-safe mechanism against unauthorised system logins.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify the pam_deny.so module is used:

    # grep '^auth' /etc/pam.d/system-auth

    Example result:

    auth required pam_faillock.so preauth
    auth sufficient pam_unix.so
    auth required pam_faillock.so authfail
    auth optional pam_faildelay.so delay=4000000
    auth required pam_deny.so

    If the pam_deny.so module is not present, or is not configured as the last auth entry, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-auth

    Add or update the following lines making sure it is present as the last auth entry:

    auth required pam_deny.so
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000267'
  tag rid: 'SV-PHTN-50-000267'
  tag stig_id: 'PHTN-50-000267'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-auth') do
    its('content') do
      auth_lines = subject.content.lines.grep(/^auth/)
      expect(auth_lines.last.strip).to match(/^auth\s+required\s+pam_deny\.so\s*$/)
    end
  end
end
