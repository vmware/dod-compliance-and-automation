control 'CDAP-10-000046' do
  title 'Cloud Director must utilize encryption when using LDAP for authentication.'
  desc  "
    Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

    Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.
  "
  desc  'rationale', ''
  desc  'check', "
    If LDAP is not being used as an identity provider, this is Not Applicable.

    From the Cloud Director provider interface, go to Administration >> Identity Providers >> LDAP.

    Review the LDAP configuration.

    If \"Use SSL\" is not enabled, this is a finding.

    For each tenant, from the Cloud Director tenant interface, go to Administration >> Identity Providers >> LDAP.

    Review the LDAP configuration.

    If \"Use SSL\" is not enabled, this is a finding.
  "
  desc  'fix', "
    The LDAP Certificates must be trusted to establish and LDAPS connection and can be done by going to Administration >> Certificate Management >> Trusted Certificates.

    Click Test Remote Connection.

    Enter the URL for the LDAP server and select LDAPS as the verification algorithm and click Connect.

    Review the presented certificate information and click Trust if it is correct.

    For either the Provider or a Tenant as an administrator go to Administration >> Identity Providers >> LDAP.

    Click Edit.

    Update the port to 636 or your appropriate LDAPS port and enable the \"Use SSL\" option then click Save.

    Note: These steps are only necessary for Tenants if \"Custom LDAP service\" is selected.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag gid: 'V-CDAP-10-000046'
  tag rid: 'SV-CDAP-10-000046'
  tag stig_id: 'CDAP-10-000046'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  result = http("https://#{input('vcdURL')}/api/org",
                method: 'GET',
                headers: {
                  'Accept' => "#{input('legacyApiVersion')}",
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
      if org['name'] == 'System'
        providerLdapSettings = http("https://#{input('vcdURL')}/api/admin/extension/settings/ldapSettings",
                                    method: 'GET',
                                    headers: {
                                      'Accept' => "#{input('legacyApiVersion')}",
                                      'Authorization' => "#{input('bearerToken')}"
                                    },
                                    ssl_verify: false)
        describe providerLdapSettings do
          its('status') { should cmp 200 }
        end
        unless providerLdapSettings.status != 200
          providerLdapSettings = JSON.parse(providerLdapSettings.body)
          if providerLdapSettings['hostName'].empty?
            describe 'LDAP not configured...skipping...' do
              skip 'LDAP not configured...skipping...'
            end
          else
            describe providerLdapSettings['isSsl'] do
              it { should cmp 'true' }
            end
            describe providerLdapSettings['port'] do
              it { should cmp '636' }
            end
          end
        end
      else
        orgLdapSettings = http("https://#{input('vcdURL')}/api/admin/org/#{orgid}/settings/ldap",
                               method: 'GET',
                               headers: {
                                 'Accept' => "#{input('legacyApiVersion')}",
                                 'Authorization' => "#{input('bearerToken')}"
                               },
                               ssl_verify: false)
        describe orgLdapSettings do
          its('status') { should cmp 200 }
        end
        unless orgLdapSettings.status != 200
          orgLdapSettings = JSON.parse(orgLdapSettings.body)
          if orgLdapSettings['customOrgLdapSettings']['hostName'].nil?
            describe 'LDAP not configured...skipping...' do
              skip 'LDAP not configured...skipping...'
            end
          else
            describe orgLdapSettings['customOrgLdapSettings']['isSsl'] do
              it { should cmp 'true' }
            end
            describe orgLdapSettings['customOrgLdapSettings']['port'] do
              it { should cmp '636' }
            end
          end
        end
      end
    end
  end
end
