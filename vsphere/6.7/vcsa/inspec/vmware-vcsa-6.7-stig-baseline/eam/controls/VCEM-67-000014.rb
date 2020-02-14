control "VCEM-67-000014" do
  title "ESX Agent Manager must not have the Web Distributed Authoring (WebDAV)
servlet installed."
  desc  "Web Distributed Authoring (WebDAV) is an extension to the HTTP
protocol that, when developed, was meant to allow users to create, change, and
move documents on a server, typically a web server or web share. WebDAV is not
widely used and has serious security concerns because it may allow clients to
modify unauthorized files on the web server and must therefore be disabled.

    Tomcat uses the org.apache.catalina.servlets.WebdavServlet servlet to
provide WebDAV services. Because the WebDAV service has been found to have an
excessive number of vulnerabilities, this servlet must not be installed. ESX
Agent Manager does not configure WebDAV by default."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000085"
  tag gid: nil
  tag rid: "VCEM-67-000014"
  tag stig_id: "VCEM-67-000014"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -n 'webdav' /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

If the command produces any output, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent
<servlet> block.

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent
<servlet-mapping> block."

  describe xml('/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml') do
    its('/web-app/servlet-mapping[servlet-name="webdav"]') { should eq [] }
  end

end

