control 'PHTN-50-000247' do
  title 'The Photon operating system must not allow empty passwords.'
  desc  'Accounts with empty or no passwords allow anyone to log on as that account without specifying a password or other forms of authentication. Allowing accounts with empty passwords puts the system at significant risk since only the username is required for access.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify empty passwords are not allowed:

    # grep nullok /etc/pam.d/system-password /etc/pam.d/system-auth

    If any results are returned indicating \"nullok\" is configured on the \"pam_unix.so\" module, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password or /etc/pam.d/system-auth

    Remove the \"nullok\" argument on the \"pam_unix.so\" module line.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000247'
  tag rid: 'SV-PHTN-50-000247'
  tag stig_id: 'PHTN-50-000247'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-password') do
    its('content') { should_not match /^password\s+.*\s+pam_unix\.so\s+(?=.*\bnullok\b).*$/ }
  end
  describe file('/etc/pam.d/system-auth') do
    its('content') { should_not match /^auth\s+.*\s+pam_unix\.so\s+(?=.*\bnullok\b).*$/ }
  end
end
