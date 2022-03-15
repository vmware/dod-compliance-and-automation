control 'VCFL-67-000015' do
  title "vSphere Client must not have the Web Distributed Authoring (WebDAV)
servlet installed."
  desc  "WebDAV is an extension to the HTTP protocol that, when developed, was
meant to allow users to create, change, and move documents on a server,
typically a web server or web share. WebDAV is not widely used and has serious
security concerns because it may allow clients to modify unauthorized files on
the web server and must therefore be disabled.

    Because the WebDAV service has been found to have an excessive number of
vulnerabilities, this servlet must not be installed. vSphere Client does not
configure WebDAV by default.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -n -i 'webdav'
/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open all listed files.

    Navigate to and locate the mapping for the JSP servlet. It is
the <servlet-mapping> node that contains <servlet-name>webdav</servlet-name>.

    Remove the WebDav servlet and any mapping associated with it.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-239756'
  tag rid: 'SV-239756r679495_rule'
  tag stig_id: 'VCFL-67-000015'
  tag fix_id: 'F-42948r679494_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml') do
    its('/web-app/servlet-mapping[servlet-name="webdav"]') { should eq [] }
  end
end
