control 'WOAT-3X-000067' do
  title 'Workspace ONE Access must set the welcome-file node to a default web page.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version. Ensuring that every document directory has an index.jsp (or equivalent) file is one approach to mitigating the vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/welcome-file-list' - 2>/dev/null|sed 's/^ *//';done

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
    <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open each file from the check that contains an unexpected or incorrect <welcome-file-list> in a text editor.

    Remove the relevant <servlet-mapping node>.

    Only /opt/vmware/horizon/workspace/conf/web.xml should have a <welcome-file-list> entry, as shown below:

    <web-app>
    ...
    <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>
    ...
    </web-app>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-WOAT-3X-000067'
  tag rid: 'SV-WOAT-3X-000067'
  tag stig_id: 'WOAT-3X-000067'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  list = ['index.html', 'index.htm', 'index.jsp']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    if fname == '/opt/vmware/horizon/workspace/conf/web.xml'
      describe xml(fname) do
        its('/web-app/welcome-file-list/welcome-file') { should be_in list }
      end
    else
      describe xml(fname) do
        its('/web-app/welcome-file-list/welcome-file') { should cmp [] }
      end
    end
  end
end
