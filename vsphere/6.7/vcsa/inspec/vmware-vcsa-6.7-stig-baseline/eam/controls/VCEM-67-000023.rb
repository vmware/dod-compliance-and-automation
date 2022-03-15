control 'VCEM-67-000023' do
  title 'ESX Agent Manager must not show directory listings.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely on
being able to obtain information about the web server's directory structure by
locating directories without default pages. In this scenario, the web server
will display to the user a listing of the files in the directory being
accessed. Ensuring that directory listing is disabled is one approach to
mitigating the vulnerability.

    In Tomcat, directory listing is disabled by default but can be enabled via
the \"listings\" parameter. Ensure that this node is not present in order to
have the default effect.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml |
sed 's/xmlns=\".*\"//g' | xmllint --xpath
'//param-name[text()=\"listings\"]/parent::init-param' -

    Expected result:

    XPath set is empty

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

    Find and remove the entire block returned in the check.

    Example:

    <init-param>
          <param-name>listings</param-name>
          <param-value>true</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-239394'
  tag rid: 'SV-239394r674676_rule'
  tag stig_id: 'VCEM-67-000023'
  tag fix_id: 'F-42586r674675_fix'
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
