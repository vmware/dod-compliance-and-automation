control 'VLIA-8X-000005' do
  title 'VMware Aria Operations for Logs must enable multifactor authentication.'
  desc  "
    Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

    Multifactor authentication requires using two or more factors to achieve authentication.

    Factors include:
    (i) something a user knows (e.g., password/PIN);
    (ii) something a user has (e.g., cryptographic identification device, token); or
    (iii) something a user is (e.g., biometric).

    A privileged account is defined as an information system account with authorizations of a privileged user.

    Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).
  "
  desc  'rationale', ''
  desc  'check', "
    Navigate to the VMware Aria Operations for Logs login page in a new browser session.

    If your Common Access Card (CAC) is inserted but you are not prompted to select a certificate or enter your PIN, this is a finding.
  "
  desc 'fix', "
    Enable Single Sign-On authentication in VMware Aria Operations for Logs.

    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> Authentication.

    Navigate to the \"Workspace ONE Access\" tab, ensure the \"Enable Single Sign-On\" radio button is enabled and the details of your Workspace ONE Access instance are correct, then click \"Save\".

    Workspace ONE Access must also be configured to support Smart Card authentication.

    See the accompanying Smart Card configuration guide for Workspace ONE Access.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000149-AU-002280'
  tag satisfies: %w[SRG-APP-000148-AU-002270 SRG-APP-000150-AU-002320 SRG-APP-000151-AU-002330 SRG-APP-000391-AU-002290]
  tag gid: 'V-VLIA-8X-000005'
  tag rid: 'SV-VLIA-8X-000005'
  tag stig_id: 'VLIA-8X-000005'
  tag cci: %w[CCI-000764 CCI-000765 CCI-000766 CCI-000767 CCI-001953]
  tag nist: ['IA-2', 'IA-2 (1)', 'IA-2 (12)', 'IA-2 (2)', 'IA-2 (3)']
  tag mitigations: "Can be achieved by integrating with vIDM.\n\nSee SRG-APP-000148-AU-002270\n\nConsider extending support for other SAML and oAuth systems."

  token = http("https://#{input('apipath')}/sessions",
               method: 'POST',
               headers: {
                 'Content-Type' => 'application/json',
                 'Accept' => 'application/json'
               },
               data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
               ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/vidm",
                    method: 'GET',
                    headers: {
                      'Content-Type' => 'application/json',
                      'Accept' => 'application/json',
                      'Authorization' => "Bearer #{sessID}"
                    },
                    ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      describe json(content: response.body) do
        its(['enabled']) { should cmp 'true' }
      end
    end
  end
end
