control 'NGNX-WB-000027' do
  title 'The NGINX web server must not be a proxy server.'
  desc  'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended.  Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc  'rationale', ''
  desc  'check', "
    Verify NGINX when used as a web server is also not a proxy server.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep -i proxy_pass

    If any proxy statements are in the output of the command, this is a finding.
  "
  desc 'fix', 'Remove and migrate any load balancer and/or reverse proxy configuration to a separate NGINX instance.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag gid: 'V-NGNX-WB-000027'
  tag rid: 'SV-NGNX-WB-000027'
  tag stig_id: 'NGNX-WB-000027'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command('nginx -T 2>&1 | grep -i proxy_pass') do
    its('stdout') { should cmp '' }
  end
end
