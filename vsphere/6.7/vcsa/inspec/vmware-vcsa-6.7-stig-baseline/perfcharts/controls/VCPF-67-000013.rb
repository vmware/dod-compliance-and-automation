control "VCPF-67-000013" do
  title "Performance Charts must not have the Web Distributed Authoring
(WebDAV) servlet installed."
  desc  "Web Distributed Authoring (WebDAV) is an extension to the HTTP
protocol that, when developed, was meant to allow users to create, change, and
move documents on a server, typically a web server or web share. WebDAV is not
widely used and has serious security concerns because it may allow clients to
modify unauthorized files on the web server and must therefore be disabled.

    Tomcat uses the org.apache.catalina.servlets.WebdavServlet servlet to
provide WebDAV services. Because the WebDAV service has been found to have an
excessive number of vulnerabilities, this servlet must not be installed.
Performance Charts does not configure WebDAV by default."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000085"
  tag gid: nil
  tag rid: "VCPF-67-000013"
  tag stig_id: "VCPF-67-000013"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -n 'webdav' /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', "Open /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml in a text
editor.

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent
<servlet> block.

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent
<servlet-mapping> block."

  describe xml('//usr/lib/vmware-perfcharts/tc-instance/conf/web.xml') do
    its('/web-app/servlet-mapping[servlet-name="webdav"]') { should eq [] }
  end

end

