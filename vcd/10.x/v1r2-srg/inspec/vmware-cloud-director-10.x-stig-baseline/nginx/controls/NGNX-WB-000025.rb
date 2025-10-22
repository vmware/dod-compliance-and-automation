control 'NGNX-WB-000025' do
  title 'NGINX must not perform user management for hosted applications.'
  desc  "
    User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logins, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify basic authentication is not enabled.

    View the running configuration by running the following command:

    #  nginx -T 2>&1 | grep auth_basic

    If any lines are returned indicating basic authentication is enabled, this is a finding.
  "
  desc 'fix', "
    Determine if the \"auth_basic\" and \"auth_basic_user_file\" directives are needed or can be safely removed.

    If they can be safely removed navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Remove the auth_basic* directives where defined.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    If they cannot be safely removed without affecting the web site then a migration plan to a more suitable authentication strategy must be devised and implemented that offloads user management functionality to an enterprise-wide solution.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: 'V-NGNX-WB-000025'
  tag rid: 'SV-NGNX-WB-000025'
  tag stig_id: 'NGNX-WB-000025'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command('nginx -T 2>&1 | grep auth_basic') do
    its('stdout') { should cmp '' }
  end
end
