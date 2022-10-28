control 'VCSA-70-000080' do
  title 'The vCenter Server must enable revocation checking for certificate based authentication.'
  desc  'The system must establish the validity of the user supplied identity certificate using OCSP and/or CRL revocation checking.'
  desc  'rationale', ''
  desc  'check', "
    If a federated identity provider is configured and used for an identity source and supports Smartcard authentication, this is Not Applicable.

    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

    Under \"Smart card authentication settings\" >> \"Certificate revocation\", verify that \"Revocation check\" does not show as disabled.

    If \"Revocation check\" shows as disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

    Under \"Smart card authentication settings\" >> \"Certificate revocation\", click the \"Edit\" button.

    Configure revocation checking per site requirements. OCSP with CRL failover is recommended.

    By default, both locations are pulled from the cert. CRL location can be overriden in this screen and local responders can be specified via the sso-config command line tool. See the supplemental document for more information.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000175'
  tag satisfies: ['SRG-APP-000392', 'SRG-APP-000401', 'SRG-APP-000403']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000080'
  tag cci: ['CCI-000185', 'CCI-001954', 'CCI-001991', 'CCI-002010']
  tag nist: ['IA-2 (12)', 'IA-5 (2) (a)', 'IA-5 (2) (d)', 'IA-8 (1)']

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
    describe 'This check is a manual or policy based check' do
      skip 'This must be reviewed manually'
    end
  end
end
