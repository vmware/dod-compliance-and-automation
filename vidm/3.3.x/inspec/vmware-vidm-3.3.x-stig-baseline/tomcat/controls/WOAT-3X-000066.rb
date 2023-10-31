control 'WOAT-3X-000066' do
  title 'Workspace ONE Access must use the setCharacterEncodingFilter filter.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. VMware utilizes the standard Tomcat SetCharacterEncodingFilter to provide a layer of defense against character encoding attacks. Filters are Java objects that performs filtering tasks on either the request to a resource (a servlet or static content), or on the response from a resource, or both.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/filter-mapping/filter-name[text()=\"setCharacterEncodingFilter\"]/parent::filter-mapping' - 2>/dev/null|sed 's/^ *//';done

    Expected result:

    /opt/vmware/horizon/workspace/webapps/acs/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/hc/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/cfg/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/mtkadmin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ws1-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/AUDIT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ROOT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/SAAS/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ws-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/conf/web.xml
    <filter-mapping>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    If the output is does not match the expected result, this is a finding.

    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/filter/filter-name[text()=\"setCharacterEncodingFilter\"]/..' - 2>/dev/null|sed 's/^ *//';done

    Expected result:

    /opt/vmware/horizon/workspace/webapps/acs/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/hc/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/cfg/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/mtkadmin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ws1-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/AUDIT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ROOT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/SAAS/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ws-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/conf/web.xml
    <filter>
        <filter-name>setCharacterEncodingFilter</filter-name>
        <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
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

    /opt/vmware/horizon/workspace/conf/web.xml

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
        </init-param>
        <init-param>
          <param-name>ignore</param-name>
          <param-value>true</param-value>
        </init-param>
        <async-supported>true</async-supported>
    </filter>

    Note: If a conflicting filter is found in another web.xml file it should be removed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: 'V-WOAT-3X-000066'
  tag rid: 'SV-WOAT-3X-000066'
  tag stig_id: 'WOAT-3X-000066'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    if fname == '/opt/vmware/horizon/workspace/conf/web.xml'
      describe xml(fname) do
        its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp '/*' }
        its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/filter-class') { should cmp 'org.apache.catalina.filters.SetCharacterEncodingFilter' }
        its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="encoding"]/param-value') { should cmp 'UTF-8' }
        its('/web-app/filter[filter-name="setCharacterEncodingFilter"]/init-param[param-name="ignore"]/param-value') { should cmp 'true' }
      end
    else
      describe xml(fname) do
        its('/web-app/filter-mapping[filter-name="setCharacterEncodingFilter"]/url-pattern') { should cmp [] }
      end
    end
  end
end
