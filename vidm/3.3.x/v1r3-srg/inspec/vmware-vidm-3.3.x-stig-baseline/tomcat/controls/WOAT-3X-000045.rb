control 'WOAT-3X-000045' do
  title 'Workspace ONE Access must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when authenticating users and processes.'
  desc  'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/local/horizon/conf/flags -name \"fips*\"

    Expected result :

    /usr/local/horizon/conf/flags/fips.mode

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # touch /usr/local/horizon/conf/flags/fips.mode

    If /usr/local/horizon/conf/flags/fips.mode.disabled was returned in the check, delete the file using following command:

    # rm /usr/local/horizon/conf/flags/fips.mode.disabled
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag gid: 'V-WOAT-3X-000045'
  tag rid: 'SV-WOAT-3X-000045'
  tag stig_id: 'WOAT-3X-000045'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe command('find /usr/local/horizon/conf/flags -name "fips*"') do
    its('stdout.strip') { should cmp '/usr/local/horizon/conf/flags/fips.mode' }
  end
end
