control 'VCUI-70-000023' do
  title 'The vSphere UI must not show directory listings.'
  desc "Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring directory listing is disabled is one approach to mitigating the vulnerability."
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' -

Expected result:

<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/web.xml

Set the <param-value> to "false" in all <param-name>listing</param-name> nodes.

Note: The setting should look like the following:

<init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
</init-param>

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-60475r889397_chk'
  tag severity: 'medium'
  tag gid: 'V-256800'
  tag rid: 'SV-256800r889399_rule'
  tag stig_id: 'VCUI-70-000023'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-60418r889398_fix'
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
