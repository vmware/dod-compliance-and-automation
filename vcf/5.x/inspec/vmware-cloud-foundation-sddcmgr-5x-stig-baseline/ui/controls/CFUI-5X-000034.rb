control 'CFUI-5X-000034' do
  title 'The SDDC Manager UI service must have Web Distributed Authoring (WebDAV) disabled.'
  desc  "
    A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # (cd /opt/vmware/vcf/sddc-manager-ui-app/server/node_modules/ && npm list 2>/dev/null | grep webdav)

    If any output is returned indicating a webdav module is installed, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # cd /opt/vmware/vcf/sddc-manager-ui-app/server/node_modules
    # npm uninstall <webdav package name>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-CFUI-5X-000034'
  tag rid: 'SV-CFUI-5X-000034'
  tag stig_id: 'CFUI-5X-000034'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command('(cd /opt/vmware/vcf/sddc-manager-ui-app/server/node_modules/ && npm list 2>/dev/null | grep webdav)') do
    its('stdout.strip') { should eq '' }
  end
end
