control 'NGNX-WB-000034' do
  title 'NGINX must have Web Distributed Authoring (WebDAV) disabled.'
  desc  "
    A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify NGINX is not complied with the WebDAV module.

    View the compiled modules by running the following command:

    # nginx -V 2>&1 | grep http_dav_module

    If the command returns any output indicating the WebDAV module is present, this is a finding.
  "
  desc 'fix', "
    NGINX does not support removing modules if it is not built and installed from source.

    The NGINX configure command is used to create a Makefile to that specifies which modules should be included in the installation.

    Consult the NGINX documentation and recompile the NGINX installation from source without the unneeded modules.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000034'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe nginx do
    its('modules') { should_not include 'http_dav' }
  end
end
