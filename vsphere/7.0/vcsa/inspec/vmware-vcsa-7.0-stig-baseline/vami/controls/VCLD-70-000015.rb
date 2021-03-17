# encoding: UTF-8

control 'VCLD-70-000015' do
  title "VAMI must not have the Web Distributed Authoring (WebDAV) servlet
installed."
  desc  "A web server can be installed with functionality that, just by its
nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to
the HTTP protocol that, when developed, was meant to allow users to create,
change, and move documents on a server, typically a web server or web share.
Allowing this functionality, development, and deployment is much easier for web
authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk
'/server\\.modules/,/\\)/'|grep mod_webdav

    If any value is returned, this is a finding.
  "
  desc  'fix', "
    Navigate to and open  /opt/vmware/etc/lighttpd/lighttpd.conf

    Delete or comment out the mod_webdav line. The line may be in an included
config and not in the parent config itself.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000015'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']
end

