control 'VCFA-9X-000356' do
  title 'VMware Cloud Foundation SDDC Manager must configure the API admin account.'
  desc  "A local account is used to access VMware Cloud Foundation APIs when the management vCenter Server is down. If you upgraded from a previous release or didn't configure the account when deploying using the API this account's password is unset. If left unset this would make managing and accessing the environment in some scenarios difficult to recover from."
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, go to Developer Center >> API Explorer.

    Locate the \"Users\" section and expand \"GET\" for \"/v1/users/local/admin\" and click \"Execute\".

    or

    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/users/local/admin' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC Manager URL and bearer token must be replaced in the example.

    Review the response and verify \"isConfigured\" is set to \"true\".

    If the \"admin@local\" account is not configured, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI, go to Developer Center >> API Explorer.

    Locate the \"Users\" section and expand \"PATCH\" for \"/v1/users/local/admin\".

    Enter the following in the value text box:

    {
        \"newPassword\": \"\",
    }

    Update the \"newPassword\" property value with an appropriate value that meets the following requirements:

    -Minimum length: 12
    -Maximum length: 127
    -At least one lowercase letter, one uppercase letter, a number, and one of the following special characters ! % @ $ ^ # ? *
    -A character cannot be repeated more than three times consecutively
    -Must not include three of the same consecutive characters

    Click \"Execute\" to set the admin API user password.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000356'
  tag rid: 'SV-VCFA-9X-000356'
  tag stig_id: 'VCFA-9X-000356'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcmgr_url')}/v1/users/local/admin",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "Bearer #{input('sddcmgr_sessionToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('isConfigured') { should cmp 'true' }
    end
  end
end
