control 'PHTN-50-000235' do
  title 'The Photon operating system must enforce password complexity on the root account.'
  desc  'Password complexity rules must apply to all accounts on the system, including root. Without specifying the enforce_for_root flag, pam_pwquality does not apply complexity rules to the root user. While root users can find ways around this requirement, given its superuser power, it is necessary to attempt to force compliance.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify password complexity is enforced for the root account:

    # grep '^enforce_for_root' /etc/security/pwquality.conf

    Example result:

    enforce_for_root

    If the \"enforce_for_root\" option is missing or commented out, this is a finding.

    Note: If pwquality.conf is not used to configure pam_pwquality.so, these options may be specified on the pwquality line in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwquality.conf

    Add or update the following lines:

    enforce_for_root
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000235'
  tag rid: 'SV-PHTN-50-000235'
  tag stig_id: 'PHTN-50-000235'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('usePwqualityConf')
    describe parse_config_file('/etc/security/pwquality.conf') do
      its('enforce_for_root') { should_not be nil }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwquality\.so\s+(?=.*\benforce_for_root\b).*$/ }
    end
  end
end
