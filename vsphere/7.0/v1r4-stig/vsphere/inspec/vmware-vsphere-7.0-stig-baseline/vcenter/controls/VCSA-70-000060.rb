control 'VCSA-70-000060' do
  title 'The vCenter Server must require multifactor authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
(i) something a user knows (e.g., password/PIN);
(ii) something a user has (e.g., cryptographic identification device, token); or
(iii) something a user is (e.g., biometric).

'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider.

If the embedded identity provider is used, click on "Smart Card Authentication".

If the embedded identity provider is used and "Smart Card Authentication" is not enabled, this is a finding.

If a third-party identity provider is used, such as Microsoft ADFS, and it does not require multifactor authentication to log on to vCenter, this is a finding.'
  desc 'fix', "To configure smart card authentication for vCenter when using the embedded identity provider, refer to the supplemental document.

For vCenter Servers using a third-party identity provider, consult the product's documentation for enabling multifactor authentication."
  impact 0.5
  tag check_id: 'C-59999r885581_chk'
  tag severity: 'medium'
  tag gid: 'V-256324'
  tag rid: 'SV-256324r885583_rule'
  tag stig_id: 'VCSA-70-000060'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-59942r885582_fix'
  tag satisfies: ['SRG-APP-000149', 'SRG-APP-000080', 'SRG-APP-000150', 'SRG-APP-000391', 'SRG-APP-000402']
  tag cci: ['CCI-000166', 'CCI-000765', 'CCI-000766', 'CCI-001953', 'CCI-002009']
  tag nist: ['AU-10', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (12)', 'IA-8 (1)']

  if input('embeddedIdp')
    command = '(Get-SsoAuthenticationPolicy).SmartCardAuthnEnabled'
    describe powercli_command(command) do
      its('stdout.strip') { should cmp 'true' }
    end
  else
    describe 'This check is a manual or policy based check' do
      skip 'This must be reviewed manually'
    end
  end
end
