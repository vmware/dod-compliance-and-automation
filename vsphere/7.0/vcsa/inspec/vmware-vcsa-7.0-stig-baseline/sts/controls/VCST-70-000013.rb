# encoding: UTF-8

control 'VCST-70-000013' do
  title "The Security Token Service must have mappings set for Java servlet
pages."
  desc  "WebDAV is an extension to the HTTP protocol that, when developed, was
meant to allow users to create, change, and move documents on a server,
typically a web server or web share. WebDAV is not widely used and has serious
security concerns because it may allow clients to modify unauthorized files on
the web server and must therefore be disabled.

    Tomcat uses the \"org.apache.catalina.servlets.WebdavServlet\" servlet to
provide WebDAV services. Because the WebDAV service has been found to have an
excessive number of vulnerabilities, this servlet must not be installed. The
Security Token Service does not configure WebDAV by default.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/servlet-mapping/servlet-name[text()=\"jsp\"]/parent::servlet-mapping'
-

    Expected result:

    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Inside the <web-app> parent node, add the following:

    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000013'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  list = ["*.jsp", "*.jspx"]
  describe xml("#{input('webXmlPath')}") do
    its('/web-app/servlet-mapping[servlet-name="jsp"]/url-pattern') { should be_in list }
  end

end

