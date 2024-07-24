control 'VRPA-8X-000056' do
  title 'The VMware Aria Operations server must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.'
  desc  "
    Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.  The use of TLS provides confidentiality of data in transit between the application server and client.

    TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    Choose \"Administrator Settings\" in the left menu, then \"FIPS 140-2 Settings\" in the center pane.

    If \"FIPS 140-2 Status\" does not show \"Activated\", this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    Choose \"Administrator Settings\" in the left menu, then \"FIPS 140-2 Settings\" in the center pane.

    Ensure \"FIPS 140-2\" is Activated, then click \"Save\".

    Note: The cluster must be offline in order to activate FIPS mode, and once FIPS mode is activated, it can never be de-activated.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag gid: 'V-VRPA-8X-000056'
  tag rid: 'SV-VRPA-8X-000056'
  tag stig_id: 'VRPA-8X-000056'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
