control 'VRPE-8X-000017' do
  title 'The vRealize Operations Manager Apache server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.'
  desc  "
    The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep ErrorDocument /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v 'SaaS' | grep -v '^#'

    Expected result:

    ErrorDocument 503 /serviceUnavailable
    ErrorDocument 404 /notFound/notFound

    If the output does not match the expected result, this is a finding.

    At the command prompt, run the following command:

    # rpm -V vmware-vcopssuite-utilities | grep -E \"notFound\\.en|serviceUnavailable\\.en\" | grep -v \"SaaS\" | grep \"^..5\"

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following lines:

    ErrorDocument 503 /serviceUnavailable
    ErrorDocument 404 /notFound/notFound

    At the command prompt, run the following command(s):

    # touch /usr/lib/vmware-vcopssuite/utilities/proxy/web/notFound/notFound.en.html
    # touch /usr/lib/vmware-vcopssuite/utilities/proxy/web/serviceUnavailable.en.html

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-VRPE-8X-000017'
  tag rid: 'SV-VRPE-8X-000017'
  tag stig_id: 'VRPE-8X-000017'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe command("grep ErrorDocument #{input('apacheConfPath')} | grep -v 'SaaS' | grep -v '^#'") do
    its('stdout.strip') { should cmp "ErrorDocument 503 /serviceUnavailable\nErrorDocument 404 /notFound/notFound" }
  end

  describe command("rpm -V vmware-vcopssuite-utilities | grep -E 'notFound\.en|serviceUnavailable\.en' | grep -v 'SaaS' | grep '^..5'") do
    its('stdout.strip') { should cmp '' }
  end
end
