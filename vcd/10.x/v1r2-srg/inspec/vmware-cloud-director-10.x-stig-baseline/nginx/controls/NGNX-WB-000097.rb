control 'NGNX-WB-000097' do
  title 'NGINX must remove references of server information from default web pages.'
  desc  "
    The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify any default web and error pages do not contain any server information.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    location / {
            root /opt/mysite/www;
            try_files $uri $uri/ /index.html;
            index index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /etc/nginx/html;
        }

    Determine if a default index page or error page has been defined by reviewing the try_files, index, and error_page directives.

    Review the default pages and ensure there is no server information such as version or server type to indicate it is an NGINX web server.

    If any default index page or error pages contains server information that reveals the server type or version, this is a finding.
  "
  desc 'fix', 'For each page that failed the check edit the file and remove any references to server type or version.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-NGNX-WB-000097'
  tag rid: 'SV-NGNX-WB-000097'
  tag stig_id: 'NGNX-WB-000097'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe 'This is a manual check...' do
    skip 'This is a manual check..'
  end
end
