control "VCEM-67-000021" do
  title "ESX Agent Manager must use the setCharacterEncodingFilter filter."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode characters into hosted applications in
an effort to break out of the document home or root home directory or to bypass
security checks. VMware utilizes the standard Tomcat SetCharacterEncodingFilter
to provide a layer of defense against character encoding attacks. Filters are
Java objects that performs filtering tasks on either the request to a resource
(a servlet or static content), or on the response from a resource, or both."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000251-WSR-000157"
  tag gid: nil
  tag rid: "VCEM-67-000021"
  tag stig_id: "VCEM-67-000021"
  tag cci: "CCI-001310"
  tag nist: ["SI-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/filter-mapping/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter-mapping'
-

Expected result:

<filter-mapping>
    <filter-name>setCharacterEncodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>

If the output is does not match the expected result, this is a finding.

At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/filter/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter'
-

Expected result:

<filter>
    <filter-name>setCharacterEncodingFilter</filter-name>

<filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
    <init-param>
      <param-name>encoding</param-name>
      <param-value>UTF-8</param-value>
      <param-name>ignore</param-name>
      <param-value>false</param-value>
    </init-param>
<async-supported>true</async-supported>
</filter>

If the output is does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Configure the <web-app> node with the child nodes listed below.

<filter-mapping>
    <filter-name>setCharacterEncodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>

<filter>
    <filter-name>setCharacterEncodingFilter</filter-name>

<filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
    <init-param>
      <param-name>encoding</param-name>
      <param-value>UTF-8</param-value>
      <param-name>ignore</param-name>
      <param-value>false</param-value>
    </init-param>
<async-supported>true</async-supported>
</filter>"

  describe xml('/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml') do
    its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '*' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
  end

end

