control 'VCPF-70-000024' do
  title 'Performance Charts must be configured to show error pages with minimal information.'
  desc 'Web servers will often display error messages to client users, including enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, Performance Charts must be configured with a catchall error handler that redirects to a standard "error.jsp".'
  desc 'check', %q(At the command prompt, run the following command:

#  xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/error-page/exception-type["text()=java.lang.Throwable"]/parent::error-page' -

Expected result:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/http_error.jsp</location>
</error-page>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

Add the following section under the <web-apps> node:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/http_error.jsp</location>
</error-page>

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-60309r888391_chk'
  tag severity: 'medium'
  tag gid: 'V-256634'
  tag rid: 'SV-256634r888393_rule'
  tag stig_id: 'VCPF-70-000024'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-60252r888392_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('statswebXmlPath')}") do
    its(['/web-app/error-page[exception-type="java.lang.Throwable"]/location']) { should cmp '/http_error.jsp' }
  end
end
