control 'PHTN-50-000059' do
  title 'The Photon operating system must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc  "
    Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

    Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

    FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify system-password is configured to encrypt representations of passwords:

    # grep sha512 /etc/pam.d/system-password

    Example result:

    password required pam_unix.so sha512 shadow use_authtok

    If the \"pam_unix.so\" module is not configured with the \"sha512\" parameter, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add or update the following line:

    password required pam_unix.so sha512 shadow use_authtok
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-PHTN-50-000059'
  tag rid: 'SV-PHTN-50-000059'
  tag stig_id: 'PHTN-50-000059'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s+(required|requisite)\s+pam_unix\.so\s+(?=.*\bsha512\b).*$/ }
  end
end
