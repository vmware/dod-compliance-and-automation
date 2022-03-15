control 'VCFL-67-000023' do
  title 'vSphere Client must not show directory listings.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely on
being able to obtain information about the web server's directory structure by
locating directories without default pages. In this scenario, the web server
will display to the user a listing of the files in the directory being
accessed. Ensuring that directory listing is disabled is one approach to
mitigating the vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format
/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'//param-name[text()=\"listings\"]/parent::init-param' -

    Expected result:

    <init-param>
          <param-name>listings</param-name>
          <param-value>false</param-value>
        </init-param>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml.

    Set the <param-value> to \"false\" in all <param-name>listing</param-name>
nodes.

    Note: The setting should look like the following:

    <init-param>
          <param-name>listings</param-name>
          <param-value>false</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-239764'
  tag rid: 'SV-239764r679519_rule'
  tag stig_id: 'VCFL-67-000023'
  tag fix_id: 'F-42956r679518_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe.one do
    describe xml('/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml') do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
    end

    describe xml('/usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml') do
      its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should cmp 'false' }
    end
  end
end
