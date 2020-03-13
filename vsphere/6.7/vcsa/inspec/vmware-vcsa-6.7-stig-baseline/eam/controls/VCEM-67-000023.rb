control "VCEM-67-000023" do
  title "ESX Agent Manager must not show directory listings."
  desc  "Enumeration techniques, such as URL parameter manipulation, rely upon
being able to obtain information about the web server's directory structure by
locating directories without default pages. In the scenario, the web server
will display to the user a listing of the files in the directory being
accessed. Ensuring that directory listing is disabled is one approach to
mitigating the vulnerability."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000142"
  tag gid: nil
  tag rid: "VCEM-67-000023"
  tag stig_id: "VCEM-67-000023"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '//param-name[text()=\"listings\"]/parent::init-param' -

Expected result:

XPath set is empty

If the output of the command does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Find and remove the entire block returned in the check.

Example:

<init-param>
      <param-name>listings</param-name>
      <param-value>true</param-value>
</init-param>"

  describe xml('/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml') do
    its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
  end

end

