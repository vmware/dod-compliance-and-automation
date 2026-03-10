control 'NGNX-WB-000062' do
  title 'NGINX must disable directory listings.'
  desc  "
    The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that no \"autoindex\" directives have been defined.

    At the command line, run the following command:

    # nginx -T 2>&1 | grep \"autoindex\"

    If the output includes any statements setting \"autoindex\" to \"on\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Remove any \"autoindex\" directives.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag satisfies: ['SRG-APP-000251-WSR-000157']
  tag gid: 'V-NGNX-WB-000062'
  tag rid: 'SV-NGNX-WB-000062'
  tag stig_id: 'NGNX-WB-000062'
  tag cci: ['CCI-001310', 'CCI-001312']
  tag nist: ['SI-10', 'SI-11 a']

  autos = command('nginx -T 2>&1 | grep "autoindex"').stdout

  if !autos.empty?
    autos.split.each do |result|
      describe result do
        it { should cmp 'autoindex off;' }
      end
    end
  else
    describe 'Directory Listings should be disabled...' do
      skip 'Directory Listings should be disabled...skipping...'
    end
  end
end
