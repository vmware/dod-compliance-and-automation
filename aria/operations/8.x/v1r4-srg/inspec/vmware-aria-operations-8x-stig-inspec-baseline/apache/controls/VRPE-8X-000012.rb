control 'VRPE-8X-000012' do
  title 'The VMware Aria Operations Apache server must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc  "
    Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

    The web server must provide FIPS-compliant encryption modules when authenticating users and processes.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep SSLFIPS /etc/httpd/conf/fips.conf | grep -v '^#'

    Expected result:

    SSLFIPS on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to https://<VROPS IP>/admin

    Login as an admin user.

    Take the cluster offline in the Administrator Settings page.

    Open the Administrator Settings tab in the left panel.

    Click Activate FIPS under the FIPS Setting section.

    Bring the cluster online.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag gid: 'V-VRPE-8X-000012'
  tag rid: 'SV-VRPE-8X-000012'
  tag stig_id: 'VRPE-8X-000012'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe command("grep SSLFIPS #{input('fipsConfPath')} | grep -v '^#'") do
    its('stdout.strip') { should cmp 'SSLFIPS on' }
  end
end
