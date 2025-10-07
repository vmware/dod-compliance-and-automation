control 'PHTN-50-000268' do
  title 'The Photon operating system must be configured to use the pam_pwhistory.so module.'
  desc  "
    Preventing password reuse increases the effectiveness of password-based authentication by forcing users to create unique passwords over time. This reduces the likelihood of successful compromise through the use of previously exposed, guessed, or shared passwords and strengthens overall system security.

    The pam_pwhistory.so module ensures that users cannot reuse recently used passwords when creating a new one.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the pam_pwhistory.so module is used:

    # grep '^password' /etc/pam.d/system-password

    Example result:

    password required pam_pwhistory.so use_authtok
    password required pam_pwquality.so use_authtok
    password required pam_unix.so sha512 shadow use_authtok

    If the pam_pwhistory.so module is not present, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add or update the following line:

    password required pam_pwhistory.so use_authtok
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000268'
  tag rid: 'SV-PHTN-50-000268'
  tag stig_id: 'PHTN-50-000268'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match(/^password\s+(required|requisite)\s+pam_pwhistory\.so\s+.*$/) }
  end
end
