control 'WOAT-3X-000068' do
  title 'Workspace ONE Access must not show directory listings.'
  desc  "
    Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability.

    In Tomcat, directory listing is disabled by default but can be enabled via the 'listings' parameter. Ensure that this node is not present in order to have the default effect.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '//param-name[text()=\"listings\"]/..' - 2>/dev/null|sed 's/^ *//';done

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
    <init-param>
    <param-name>listings</param-name>
    <param-value>false</param-value>
    </init-param>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open each file from the check that contains an unexpected or incorrect <init-param> in a text editor.

    Only /opt/vmware/horizon/workspace/conf/web.xml should have a <init-param> entry, as shown below:

    <init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: 'V-WOAT-3X-000068'
  tag rid: 'SV-WOAT-3X-000068'
  tag stig_id: 'WOAT-3X-000068'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    if fname == '/opt/vmware/horizon/workspace/conf/web.xml'
      describe.one do
        describe xml(fname) do
          its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
        end

        describe xml(fname) do
          its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should cmp 'false' }
        end
      end
    else
      describe xml(fname) do
        its('/web-app/servlet/init-param[param-name="listings"]/param-value') { should eq [] }
      end
    end
  end
end
