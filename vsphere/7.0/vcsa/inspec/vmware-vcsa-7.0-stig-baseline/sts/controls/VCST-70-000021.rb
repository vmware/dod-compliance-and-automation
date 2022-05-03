control 'VCST-70-000021' do
  title 'The Security Token Service must use the "setCharacterEncodingFilter" filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. VMware uses the standard Tomcat \"SetCharacterEncodingFilter\" to provide a layer of defense against character encoding attacks. Filters are Java objects that perform filtering tasks on either the request to a resource (a servlet or static content), or on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2 s/xmlns=\".*\"//g' | xmllint --xpath '/web-app/filter-mapping/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter-mapping' -

    Expected result:

    <filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    If the output is does not match the expected result, this is a finding.

    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2 s/xmlns=\".*\"//g' | xmllint --xpath '/web-app/filter/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter' -

    Expected result:

       <filter>
          <filter-name>setCharacterEncodingFilter</filter-name>
          <filter-class>
             org.apache.catalina.filters.SetCharacterEncodingFilter
          </filter-class>
          <init-param>
             <param-name>encoding</param-name>
             <param-value>UTF-8</param-value>
          </init-param>
          <init-param>
             <param-name>ignore</param-name>
             <param-value>true</param-value>
          </init-param>
          <async-supported>true</async-supported>
       </filter>

    If the output is does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Configure the <web-app> node with the child nodes listed below:

    <filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

       <filter>
          <filter-name>setCharacterEncodingFilter</filter-name>
          <filter-class>
             org.apache.catalina.filters.SetCharacterEncodingFilter
          </filter-class>
          <init-param>
             <param-name>encoding</param-name>
             <param-value>UTF-8</param-value>
          </init-param>
          <init-param>
             <param-name>ignore</param-name>
             <param-value>true</param-value>
          </init-param>
          <async-supported>true</async-supported>
       </filter>

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000021'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
  end
end
