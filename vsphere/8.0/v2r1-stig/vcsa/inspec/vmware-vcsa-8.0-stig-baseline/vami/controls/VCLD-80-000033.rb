control 'VCLD-80-000033' do
  title 'The vCenter VAMI service must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, VAMI could deliver sensitive files.'
  desc 'check', 'At the command prompt, run the following command:

# grep "url.access-deny" /var/lib/vmware/cap-lighttpd/lighttpd.conf

Example result:

url.access-deny = ( "~", ".inc" )

If "url.access-deny" is not set to "( "~", ".inc" )", this is a finding.

Note: The command must be run from a bash shell and not from a shell generated by the "appliance shell". Use the "chsh" command to change the shell for the account to "/bin/bash". Refer to KB Article 2100508 for more details:

https://kb.vmware.com/s/article/2100508'
  desc 'fix', 'Navigate to and open:

/var/lib/vmware/cap-lighttpd/lighttpd.conf

Add or reconfigure the following value:

url.access-deny = ( "~", ".inc" )

Restart the service with the following command:

# systemctl restart cap-lighttpd'
  impact 0.5
  tag check_id: 'C-62884r1003698_chk'
  tag severity: 'medium'
  tag gid: 'V-259144'
  tag rid: 'SV-259144r1003700_rule'
  tag stig_id: 'VCLD-80-000033'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-62793r1003699_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe parse_config_file(input('lighttpdConf')).params['url.access-deny'] do
    it { should cmp '( "~", ".inc" )' }
  end
end
