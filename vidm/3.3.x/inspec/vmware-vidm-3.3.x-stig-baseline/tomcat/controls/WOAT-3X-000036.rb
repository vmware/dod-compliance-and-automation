control 'WOAT-3X-000036' do
  title 'Workspace ONE Access must have mappings set for Java servlet pages.'
  desc  "
    Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc.

    As Tomcat is a java-based web server, the main file extension used is *.jsp.  This check ensures that the *.jsp file type has been properly mapped to servlets.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/servlet-mapping/url-pattern[text()=\"*.jsp\"]/..' - 2>/dev/null|sed 's/^ *//';done

    Expected result:

    /opt/vmware/horizon/workspace/webapps/ws1-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ROOT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/SAAS/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/acs/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/hc/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/ws-admin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/AUDIT/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/mtkadmin/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/webapps/cfg/WEB-INF/web.xml
    /opt/vmware/horizon/workspace/conf/web.xml
    <servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open each file from the check that contains an unexpected or incorrect <servlet-mapping> in a text editor.

    Remove the relevant <servlet-mapping node>.

    Only /opt/vmware/horizon/workspace/conf/web.xml should have a mapping for *.jsp and *.jspx, as shown below:

    <web-app>
    ...
    <servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>
    ...
    </web-app>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag gid: 'V-WOAT-3X-000036'
  tag rid: 'SV-WOAT-3X-000036'
  tag stig_id: 'WOAT-3X-000036'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  list = ['*.jsp', '*.jspx']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    if fname == '/opt/vmware/horizon/workspace/conf/web.xml'
      describe xml(fname) do
        its('/web-app/servlet-mapping[servlet-name="jsp"]/url-pattern') { should be_in list }
      end
    else
      describe xml(fname) do
        its('/web-app/servlet-mapping/url-pattern') { should_not be_in list }
      end
    end
  end
end
