control 'NMGR-4X-000015' do
  title 'The NSX Manager must be configured to integrate with an identity provider that supports multifactor authentication (MFA).'
  desc 'Common attacks against single-factor authentication are attacks on user passwords. These attacks include brute force password guessing, password spraying, and password credential stuffing. This requirement also supports nonrepudiation of actions taken by an administrator.

This requirement ensures the NSX Manager is configured to use a centralized authentication services to authenticate users prior to granting administrative access.

As of NSX 4.1 and vCenter 8.0 Update 2, NSX Manager administrator access can also be configured by connecting VMware NSX to the Workspace ONE Access Broker in VMware vCenter for federated identity. Refer to the NSX product documentation to configure this access option.

'
  desc 'check', 'From the NSX Manager web interface, go to System >> Settings >> Users Management >> Authentication Providers.

Verify that the "VMware Identity Manager" and "OpenID Connect" tabs are configured.

If NSX is not configured to integrate with an identity provider that supports MFA, this is a finding.'
  desc 'fix', 'To configure NSX to integrate with VMware Identity Manager or Workspace ONE Access, as the authentication source, do the following:

From the NSX Manager web interface, go to System >> Users and Roles >> VMware Identity Manager and click "Edit".

If using an external load balancer for the NSX Management cluster, enable "External Load Balancer Integration". If using a cluster VIP, leave this disabled.

Click the toggle button to enable "VMware Identity Manager Integration".

Enter the VMware Identity Manager or Workspace ONE Access appliance name, OAuth Client ID, OAuth Client Secret, and certificate thumbprint as provided by the administrators.

Enter the NSX Appliance FQDN. For a cluster, enter the load balancer FQDN or cluster VIP FQDN.

Click "Save", import users and groups, and then assign them roles. (The users are not actually local and remain in the authentication/AAA server.)

Note: As of NSX 4.1 and vCenter 8.0 Update 2, NSX Manager administrator access can also be configured by connecting VMware NSX to the Workspace ONE Access Broker in VMware vCenter for federated identity. Refer to the NSX product documentation to configure this access option.

Ensure the identity provider administrators have configured the provider to support multi-factor authentication.'
  impact 0.7
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69213r994109_chk'
  tag severity: 'high'
  tag gid: 'V-265296'
  tag rid: 'SV-265296r994111_rule'
  tag stig_id: 'NMGR-4X-000015'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-69121r994110_fix'
  tag satisfies: ['SRG-APP-000080-NDM-000220', 'SRG-APP-000149-NDM-000247', 'SRG-APP-000516-NDM-000336']
  tag 'documentable'
  tag cci: ['CCI-000166', 'CCI-000765', 'CCI-000370']
  tag nist: ['AU-10', 'IA-2 (1)', 'CM-6 (1)']

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
