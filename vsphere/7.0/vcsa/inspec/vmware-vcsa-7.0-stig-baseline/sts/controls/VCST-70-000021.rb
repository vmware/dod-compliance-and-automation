# encoding: UTF-8

control 'VCST-70-000021' do
  title "The Security Token Service must use the \"setCharacterEncodingFilter\"
filter."
  desc  "Enumeration techniques, such as URL parameter manipulation, rely on
being able to obtain information about the web server's directory structure by
locating directories without default pages. In this scenario, the web server
will display to the user a listing of the files in the directory being
accessed. By having a default hosted application web page, the anonymous web
user will not obtain directory browsing information or an error message that
reveals the server type and version. Ensuring that every document directory has
an \"index.jsp\" (or equivalent) file is one approach to mitigating the
vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/filter-mapping/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter-mapping'
-

    Expected result:

    <filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    If the output is does not match the expected result, this is a finding.

    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/filter/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter'
-

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
  desc  'fix', "
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
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000021'
  tag fix_id: nil
  tag cci: 'CCI-001310'
  tag nist: ['SI-10']

  describe xml("#{input('webXmlPath')}") do
    its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
    its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
  end

end

