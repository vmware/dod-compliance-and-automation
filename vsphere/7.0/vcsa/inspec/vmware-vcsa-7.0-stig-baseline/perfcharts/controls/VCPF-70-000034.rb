control 'VCPF-70-000034' do
  title 'Performance Charts default servlet must be set to readonly.'
  desc  "
    The default servlet (or DefaultServlet) is a special servlet provided with Tomcat which is called when no other suitable page is found in a particular folder. The DefaultServlet serves static resources as well as directory listings. The DefaultServlet is configured by default with the \"readonly\" parameter set to \"true\" where HTTP commands like PUT and DELETE are rejected.

    Changing this to false allows clients to delete or modify static resources on the server and to upload new resources. DefaultServlet readonly must be set to true, either literally or by absence (default).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/servlet/servlet-name[text()=\"default\"]/../init-param/param-name[text()=\"readonly\"]/../param-value[text()=\"false\"]' -

    Expected result:

    XPath set is empty

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml

    Navigate to the /<web-apps>/<servlet>/<servlet-name>default</servlet-name>/ node and remove the following node:

    <init-param>
          <param-name>readonly</param-name>
          <param-value>false</param-value>
    </init-param>

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000034'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/servlet[servlet-name="default"]/init-param[param-name="readonly"]/param-value') { should eq [] }
  end
end
