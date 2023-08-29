control 'WOAT-3X-000037' do
  title 'Workspace ONE Access must not have the Web Distributed Authoring (WebDAV) servlet installed.'
  desc  "
    Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server and must therefore be disabled.

    Tomcat uses the org.apache.catalina.servlets.WebdavServlet servlet to provide WebDAV services. Because the WebDAV service has been found to have an excessive number of vulnerabilities, this servlet must not be installed. Workspace ONE Access does not configure WebDAV by default.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml;grep -webdav $xml|wc -l;done

    If any discovered web.xml is followed by a line with non-zero number, this is a finding.
  "
  desc 'fix', "
    Open each file from the check with a non-zero count of found webdav instances in a text editor.

    Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet> block.

    Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet-mapping> block.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-WOAT-3X-000037'
  tag rid: 'SV-WOAT-3X-000037'
  tag stig_id: 'WOAT-3X-000037'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    describe xml(fname) do
      its('/web-app/servlet-mapping[servlet-name="webdav"]') { should eq [] }
    end
  end
end
