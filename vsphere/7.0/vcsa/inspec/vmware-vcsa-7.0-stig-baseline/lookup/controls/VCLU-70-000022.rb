control 'VCLU-70-000022' do
  title 'The Lookup Service must not show directory listings.'
  desc %q(Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability.

In Tomcat, directory listing is disabled by default but can be enabled via the "listings" parameter. Ensure this node is not present to have the default effect.)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/..' -

Expected result:

<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/web.xml

Set the <param-value> to "false" in all <param-name>listing</param-name> nodes.

The setting should look like the following:

<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60402r888770_chk'
  tag severity: 'medium'
  tag gid: 'V-256727'
  tag rid: 'SV-256727r888772_rule'
  tag stig_id: 'VCLU-70-000022'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-60345r888771_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe.one do
    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
    end

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should cmp 'false' }
    end
  end
end
