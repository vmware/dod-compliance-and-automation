control 'VCPF-80-000137' do
  title 'The vCenter Perfcharts service directory listings parameter must be disabled.'
  desc %q(Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability.

In Tomcat, directory listing is disabled by default but can be enabled via the "listings" parameter. Ensure this node is not present to have the default effect.)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '//param-name[text()="listings"]/parent::init-param' -

Example result:

XPath set is empty

If the "listings" parameter is specified and is not "false", this is a finding.

If the "listings" parameter does not exist, this is not a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

Find and remove the entire block returned in the check.

Example:

<init-param>
      <param-name>listings</param-name>
      <param-value>true</param-value>
</init-param>

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-62833r934935_chk'
  tag severity: 'medium'
  tag gid: 'V-259093'
  tag rid: 'SV-259093r960963_rule'
  tag stig_id: 'VCPF-80-000137'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62742r934936_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml(input('webXmlPath'))

  # find the DefaultServlet, if there, then find the 'listings' parent node (init-param) and get its param-value (default is 'false' if not present)
  describe xmlconf['/web-app/servlet/init-param[param-name="listings"]/param-value'] do
    it { should be_in ['', 'false'] }
  end
end
