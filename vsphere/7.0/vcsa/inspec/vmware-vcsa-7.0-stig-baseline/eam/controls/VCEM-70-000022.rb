control 'VCEM-70-000022' do
  title 'ESX Agent Manager must set the welcome-file node to a default web page.'
  desc %q(Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed.

By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version. Ensuring every document directory has an "index.jsp" (or equivalent) file is one approach to mitigating the vulnerability.)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/welcome-file-list' -

Expected result:

<welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Add the following section under the <web-apps> node:

<welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
</welcome-file-list>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-60369r888636_chk'
  tag severity: 'medium'
  tag gid: 'V-256694'
  tag rid: 'SV-256694r888638_rule'
  tag stig_id: 'VCEM-70-000022'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-60312r888637_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  list = ['index.jsp']
  describe xml("#{input('webXmlPath')}") do
    its('/web-app/welcome-file-list/welcome-file') { should be_in list }
  end
end
