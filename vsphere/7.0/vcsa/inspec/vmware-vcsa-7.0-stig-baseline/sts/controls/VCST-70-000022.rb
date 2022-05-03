control 'VCST-70-000022' do
  title 'The Security Token Service must set the welcome-file node to a default web page.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version. Ensuring that every document directory has an \"index.jsp\" (or equivalent) file is one approach to mitigating the vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2 s/xmlns=\".*\"//g' | xmllint --xpath '/web-app/welcome-file-list' -

    Expected result:

    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
        <welcome-file>index.htm</welcome-file>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Add the following section under the <web-apps> node:

    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
        <welcome-file>index.htm</welcome-file>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000022'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  list = ['index.jsp', 'index.html', 'index.htm']
  describe xml("#{input('webXmlPath')}") do
    its('/web-app/welcome-file-list/welcome-file') { should be_in list }
  end
end
