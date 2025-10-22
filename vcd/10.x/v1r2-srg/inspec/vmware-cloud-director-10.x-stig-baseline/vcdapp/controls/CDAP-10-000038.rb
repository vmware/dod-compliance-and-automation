control 'CDAP-10-000038' do
  title 'Cloud Director must use an enterprise user management system to uniquely identify and authenticate users.'
  desc  "
    To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated.  This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

    To ensure support to the enterprise, the authentication must utilize an enterprise solution. Cloud Director supports this in multiple ways for the Provider and for Tenants with support for SAML, LDAPS, and OIDC based identity providers. Should multi-factor authentication be required SAML or OIDC must be used.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Identity Providers.

    Review the SAML, LDAP, and OIDC sections.

    If none of the available identity providers are configured for use in the provider interface, this is a finding.

    For each tenant, from the Cloud Director tenant interface, go to Administration >> Identity Providers.

    Review the SAML, LDAP, and OIDC sections.

    If none of the available identity providers are configured for use in a tenants organization, this is a finding.
  "
  desc  'fix', "
    For either the Provider or a Tenant as an administrator go to Administration >> Identity Providers.

    Select the Identity Provider of choice and click Configure.

    Enter the required information for the Identity Provider and click Save.

    Users and Groups may now be imported into Cloud Director and assigned roles and used for logins.

    Note: For more information on a specific Identity Provider and configuration refer to the product documentation.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag satisfies: ['SRG-APP-000080-AS-000045', 'SRG-APP-000149-AS-000102', 'SRG-APP-000177-AS-000126', 'SRG-APP-000705-AS-000110', 'SRG-APP-000820-AS-000170', 'SRG-APP-000825-AS-000180']
  tag gid: 'V-CDAP-10-000038'
  tag rid: 'SV-CDAP-10-000038'
  tag stig_id: 'CDAP-10-000038'
  tag cci: ['CCI-000166', 'CCI-000187', 'CCI-000764', 'CCI-000765', 'CCI-003628', 'CCI-004046', 'CCI-004047']
  tag nist: ['AC-2 (3) (b)', 'AU-10', 'IA-2', 'IA-2 (1)', 'IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-5 (2) (a) (2)']

  result = http("https://#{input('vcdURL')}/api/org",
                method: 'GET',
                headers: {
                  'accept' => "#{input('legacyApiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    orgs = JSON.parse(result.body)
    orgs['org'].each do |org|
      orgid = org['href'].scan(%r{.*org/(.*)}).flatten[0]
      orgsettings = http("https://#{input('vcdURL')}/api/admin/org/#{orgid}/settings",
                         method: 'GET',
                         headers: {
                           'accept' => "#{input('legacyApiVersion')}",
                           'Authorization' => "#{input('bearerToken')}"
                         },
                         ssl_verify: false)
      if org['name'] == 'System'
        providerLdapSettings = http("https://#{input('vcdURL')}/api/admin/extension/settings/ldapSettings",
                                    method: 'GET',
                                    headers: {
                                      'accept' => "#{input('legacyApiVersion')}",
                                      'Authorization' => "#{input('bearerToken')}"
                                    },
                                    ssl_verify: false)
        describe orgsettings do
          its('status') { should cmp 200 }
        end
        describe providerLdapSettings do
          its('status') { should cmp 200 }
        end
        unless orgsettings.status != 200 && providerLdapSettings.status != 200
          orgsettings = JSON.parse(orgsettings.body)
          providerLdapSettings = JSON.parse(providerLdapSettings.body)
          describe.one do
            describe 'Checking provider LDAP settings' do
              subject { providerLdapSettings }
              its(['hostname']) { should_not be_empty }
            end
            describe 'Checking org Federation Settings' do
              subject { orgsettings['orgFederationSettings'] }
              its(['enabled']) { should cmp 'true' }
            end
            describe 'Checking org OAuth Settings' do
              subject { orgsettings['orgOAuthSettings'] }
              its(['enabled']) { should_not cmp nil }
            end
          end
        end
      else
        describe orgsettings do
          its('status') { should cmp 200 }
        end
        unless orgsettings.status != 200
          orgsettings = JSON.parse(orgsettings.body)
          describe.one do
            describe orgsettings['orgLdapSettings'] do
              its(['orgLdapMode']) { should_not cmp 'NONE' }
            end
            describe orgsettings['orgFederationSettings'] do
              its(['enabled']) { should cmp 'true' }
            end
            describe orgsettings['orgOAuthSettings'] do
              its(['enabled']) { should_not cmp nil }
            end
          end
        end
      end
    end
  end
end
