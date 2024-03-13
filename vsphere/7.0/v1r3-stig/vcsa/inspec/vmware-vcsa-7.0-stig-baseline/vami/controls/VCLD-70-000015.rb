control 'VCLD-70-000015' do
  title 'VAMI must not have the Web Distributed Authoring (WebDAV) servlet installed.'
  desc 'A web server can be installed with functionality that, by its nature, is not secure. WebDAV is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', %q[At the command prompt, run the following command:

# /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\\)/'|grep mod_webdav

If any value is returned, this is a finding.

Note: The command must be run from a bash shell and not from a shell generated by the "appliance shell". Use the "chsh" command to change the shell for the account to "/bin/bash". Refer to KB Article 2100508 for more details:

https://kb.vmware.com/s/article/2100508]
  desc 'fix', 'Navigate to and open:

 /opt/vmware/etc/lighttpd/lighttpd.conf

Delete or comment out the "mod_webdav" line.

Note: The line may be in an included config and not in the parent config itself.

Restart the service with the following command:

# vmon-cli --restart applmgmt'
  impact 0.5
  tag check_id: 'C-60334r888497_chk'
  tag severity: 'medium'
  tag gid: 'V-256659'
  tag rid: 'SV-256659r888499_rule'
  tag stig_id: 'VCLD-70-000015'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-60277r888498_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  command("/opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|awk '/server\.modules/,/\)/'|sed -e 's/^[ ]*//'|grep mod_").stdout.split.each do |result|
    describe result do
      it { should_not cmp 'mod_webdav' }
    end
  end
end