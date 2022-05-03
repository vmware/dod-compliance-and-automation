control 'VCUI-70-000014' do
  title 'vSphere UI must not have the Web Distributed Authoring (WebDAV) servlet installed.'
  desc  "
    WebDAV is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server and must therefore be disabled.

    Tomcat uses the \"org.apache.catalina.servlets.WebdavServlet\" servlet to provide WebDAV services. Because the WebDAV service has been found to have an excessive number of vulnerabilities, this servlet must not be installed. vSphere UI does not configure WebDAV by default.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -n 'webdav' /usr/lib/vmware-vsphere-ui/server/conf/web.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/web.xml.

    Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet> block.

    Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet-mapping> block.

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000014'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/servlet-mapping[servlet-name="webdav"]') { should eq [] }
  end
end
