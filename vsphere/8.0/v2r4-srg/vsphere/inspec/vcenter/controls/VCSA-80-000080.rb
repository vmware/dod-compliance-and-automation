control 'VCSA-80-000080' do
  title 'The vCenter Server must enable revocation checking for certificate-based authentication.'
  desc 'The system must establish the validity of the user-supplied identity certificate using Online Certificate Status Protocol (OCSP) and/or Certificate Revocation List (CRL) revocation checking.

'
  desc 'check', 'If a federated identity provider is configured and used for an identity source and supports smart card authentication, this is not applicable.

From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

Under Smart Card Authentication settings >> Certificate Revocation, verify "Revocation check" does not show as disabled.

If "Revocation check" shows as disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

Under Smart Card Authentication settings >> Certificate Revocation, click the "Edit" button.

Configure revocation checking per site requirements. OCSP with CRL failover is recommended.

Note: If FIPS mode is enabled on vCenter, OCSP revocation validation may not function and CRL bay be used instead.

By default, both locations are pulled from the cert. CRL location can be overridden in this screen, and local responders can be specified via the sso-config command line tool. Refer to the vSphere documentation for more information.'
  impact 0.5
  tag check_id: 'C-62659r1003598_chk'
  tag severity: 'medium'
  tag gid: 'V-258919'
  tag rid: 'SV-258919r1003600_rule'
  tag stig_id: 'VCSA-80-000080'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-62568r1003599_fix'
  tag satisfies: ['SRG-APP-000175', 'SRG-APP-000392', 'SRG-APP-000401', 'SRG-APP-000403']
  tag cci: ['CCI-000185', 'CCI-001954', 'CCI-004068', 'CCI-002010']
  tag nist: ['IA-5 (2) (b) (1)', 'IA-2 (12)', 'IA-5 (2) (b) (2)', 'IA-8 (1)']

  if input('embeddedIdp')
    describe.one do
      describe powercli_command('(Get-SsoAuthenticationPolicy).OCSPEnabled') do
        its('stdout.strip') { should cmp 'true' }
      end
      describe powercli_command('(Get-SsoAuthenticationPolicy).UseInCertCRL') do
        its('stdout.strip') { should cmp 'true' }
      end
      describe powercli_command('(Get-SsoAuthenticationPolicy).CRLUrl') do
        its('stdout.strip') { should_not cmp '' }
      end
    end
  else
    describe 'This check is a manual or policy based check and must be reviewed manually.' do
      skip 'This check is a manual or policy based check and must be reviewed manually.'
    end
  end
end
