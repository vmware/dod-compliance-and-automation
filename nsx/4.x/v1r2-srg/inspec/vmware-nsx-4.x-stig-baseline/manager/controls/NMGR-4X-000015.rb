control 'NMGR-4X-000015' do
  title 'The NSX Manager must be configured to integrate with an identity provider that supports Multi-factor authentication (MFA).'
  desc  "
    This requirement supports nonrepudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

    Multi-factor authentication (MFA) is when two or more factors are used to confirm the identity of an individual who is requesting access to digital information resources. Valid factors include something the individual knows (e.g., username and password), something the individual has (e.g., a smartcard or token), or something the individual is (e.g., a fingerprint or biometric). Legacy information system environments only use a single factor for authentication, typically a username and password combination. Although two pieces of data are used in a username and password combination, this is still considered single factor because an attacker can obtain access simply by learning what the user knows. Common attacks against single-factor authentication are attacks on user passwords. These attacks include brute force password guessing, password spraying, and password credential stuffing. MFA, along with strong user account hygiene, helps mitigate against the threat of having account passwords discovered by an attacker. Even in the event of a password compromise, with MFA implemented and required for interactive login, the attacker still needs to acquire something the user has or replicate a piece of user’s biometric digital presence.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Settings >> Users Management >> Authentication Providers.

    Review the \"VMware Identity Manager\" and \"OpenID Connect\" tabs.

    If NSX is not configured to use a \"VMware Identity Manager\" or \"OpenID Connect\" identity provider that is configured to support MFA, this is a finding.
  "
  desc 'fix', "
    To configure NSX to integrate with VMware Identity Manager or Workspace ONE Access as the authentication source, do the following:

    From the NSX Manager web interface, go to System >> Users and Roles >> VMware Identity Manager and click \"Edit\".

    If using an external load balancer for the NSX Management cluster, enable \"External Load Balancer Integration\". If using a cluster VIP, leave this disabled.

    Click the toggle button to enable \"VMware Identity Manager Integration\".

    Enter the VMware Identity Manager or Workspace ONE Access appliance name, OAuth Client ID, OAuth Client Secret, and certificate thumbprint as provided by the administrators.

    Enter the NSX Appliance FQDN. For a cluster, enter the load balancer FQDN or cluster VIP FQDN.

    Click \"Save\", import users and groups, and then assign them roles.

    As of NSX 4.1 and vCenter 8.0 Update 2 you can allow users access to log in to NSX Manager by connecting VMware NSX to the Workspace ONE Access Broker in VMware vCenter for federated identity. To configure this please reference the NSX product documentation.

    Ensure the identity provider administrators have configured the provider to support multi-factor authentication.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag satisfies: ['SRG-APP-000149-NDM-000247', 'SRG-APP-000516-NDM-000336']
  tag gid: 'V-NMGR-4X-000015'
  tag rid: 'SV-NMGR-4X-000015'
  tag stig_id: 'NMGR-4X-000015'
  tag cci: ['CCI-000166', 'CCI-000370', 'CCI-000765']
  tag nist: ['AU-10', 'CM-6 (1)', 'IA-2 (1)']

  resultvidm = http("https://#{input('nsxManager')}/api/v1/node/aaa/providers/vidm",
                    method: 'GET',
                    headers: {
                      'Accept' => 'application/json',
                      'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                      'Cookie' => "#{input('sessionCookieId')}"
                    },
                    ssl_verify: false)

  resultoidc = http("https://#{input('nsxManager')}/api/v1/trust-management/oidc-uris",
                    method: 'GET',
                    headers: {
                      'Accept' => 'application/json',
                      'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                      'Cookie' => "#{input('sessionCookieId')}"
                    },
                    ssl_verify: false)

  describe resultvidm do
    its('status') { should cmp 200 }
  end
  describe resultoidc do
    its('status') { should cmp 200 }
  end
  unless resultvidm.status != 200 && resultoidc.status != 200
    describe.one do
      describe json(content: resultvidm.body) do
        its('vidm_enable') { should cmp 'true' }
      end
      describe json(content: resultoidc.body) do
        its('results') { should_not be_empty }
      end
    end
  end
end
