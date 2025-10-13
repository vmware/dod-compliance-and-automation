control 'PHTN-50-000265' do
  title 'The Photon operating system must enforce password history on the root account.'
  desc  'Password history rules must apply to all accounts on the system, including root. Without specifying the enforce_for_root flag, pam_pwhistory does not apply history rules to the root user.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify password history is enforced for the root account:

    # grep '^enforce_for_root' /etc/security/pwhistory.conf

    Example result:

    enforce_for_root

    If the \"enforce_for_root\" option is missing or commented out, this is a finding.

    Note: If pwhistory.conf is not used to configure pam_pwhistory.so, these options may be specified on the pwhistory line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwhistory.conf

    Add or update the following lines:

    enforce_for_root
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000265'
  tag rid: 'SV-PHTN-50-000265'
  tag stig_id: 'PHTN-50-000265'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('usePwhistoryConf')
    describe parse_config_file('/etc/security/pwhistory.conf') do
      its('enforce_for_root') { should_not be nil }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match(/^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\benforce_for_root\b).*$/) }
    end
  end
end
