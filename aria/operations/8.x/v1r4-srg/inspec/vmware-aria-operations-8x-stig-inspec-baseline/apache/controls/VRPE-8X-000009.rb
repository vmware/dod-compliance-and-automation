control 'VRPE-8X-000009' do
  title 'The VMware Aria Operations Apache server must have Web Distributed Authoring (WebDAV) disabled.'
  desc  "
    A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality makes development and deployment much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow unauthorized clients to modify files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # httpd -M 2>/dev/null | grep dav_

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Remove the lines that load prohibited modules from the check.

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-VRPE-8X-000009'
  tag rid: 'SV-VRPE-8X-000009'
  tag stig_id: 'VRPE-8X-000009'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command('httpd -M 2>/dev/null | grep dav_') do
    its('stdout.strip') { should cmp '' }
  end
end
