control 'PHTN-40-000206' do
  title 'The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', "At the command line, run the following command to verify the pam_faildelay.so module is used:

# grep '^auth' /etc/pam.d/system-auth

Example result:

auth required pam_faillock.so preauth
auth required pam_unix.so
auth required pam_faillock.so authfail
auth optional pam_faildelay.so delay=4000000

If the pam_faildelay.so module is not present with the delay set to at least four seconds, this is a finding.

Note: The delay is configured in microseconds."
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-auth

Add or update the following line:

auth optional pam_faildelay.so delay=4000000

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62609r1003653_chk'
  tag severity: 'medium'
  tag gid: 'V-258869'
  tag rid: 'SV-258869r1003654_rule'
  tag stig_id: 'PHTN-40-000206'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-62518r933667_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /^auth\s+(required|requisite|optional)\s+pam_faildelay\.so\s+(?=.*\bdelay=4000000\b).*$/ }
  end
end
