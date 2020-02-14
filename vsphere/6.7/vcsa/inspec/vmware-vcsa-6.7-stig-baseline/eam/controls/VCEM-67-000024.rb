control "VCEM-67-000024" do
  title "ESX Agent Manager must configured to show error pages with minimal
information."
  desc  "Web servers will often display error messages to client users
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.
This information could be used by an attacker to blueprint what type of attacks
might be successful. As such, the Security Token Service must be configured
with a catch-all error handler that redirects to a standard error.jsp."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000159"
  tag gid: nil
  tag rid: "VCEM-67-000024"
  tag stig_id: "VCEM-67-000024"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

#  xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/error-page/exception-type[\"text()=java.lang.Throwable\"]/parent::error-page'
-

Expected result:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/error.jsp</location>
  </error-page>

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open
/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Add the following section under the <web-apps> node:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/error.jsp</location>
  </error-page>
"

  describe xml('/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml') do
    its(['/web-app/error-page[exception-type="java.lang.Throwable"]/location']) { should cmp '/error.jsp' }
  end

end

