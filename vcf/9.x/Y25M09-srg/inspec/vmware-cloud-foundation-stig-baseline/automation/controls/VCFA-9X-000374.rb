control 'VCFA-9X-000374' do
  title 'VMware Cloud Foundation Automation must disable tenant branding on login and logout pages.'
  desc  'To avoid disclosing the existence of other tenants, individual tenant branding must not be displayed on the login and logout screens and should only be shown once logged in.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Automation is not deployed, this is not applicable.

    From the VCF Automation Provider interface, go to Administration >> Branding.

    Click \"Settings\" and review the \"Enable Login and Logout Page Branding\" option.

    If \"Enable Login and Logout Page Branding\" is enabled, this is a finding.
  "
  desc 'fix', "
    From the VCF Automation Provider interface, go to Administration >> Branding.

    Click \"Settings\" and disable \"Enable Login and Logout Page Branding\" then click \"Save\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000374'
  tag rid: 'SV-VCFA-9X-000374'
  tag stig_id: 'VCFA-9X-000374'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('automation_deployed')
    result = http("https://#{input('automation_url')}/cloudapi/1.0.0/site/configurations/urn:vcloud:configuration:backend.branding.requireAuthForBranding",
                  method: 'GET',
                  headers: {
                    'Accept' => "#{input('automation_apiVersion')}",
                    'Authorization' => "Bearer #{input('automation_sessionToken')}"
                  },
                  ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      loginBranding = JSON.parse(result.body)
      # If branding has never been turned on for login/logout pages there is no value returned by default.
      if !loginBranding['typedValue'].nil?
        describe 'Branding on login and logout pages' do
          subject { loginBranding['typedValue']['value'] }
          it { should cmp 'true' }
        end
      else
        describe 'Branding on login and logout pages' do
          subject { loginBranding['typedValue'] }
          it { should cmp nil }
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Automation is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Automation is not deployed in the target environment. This control is N/A.'
    end
  end
end
