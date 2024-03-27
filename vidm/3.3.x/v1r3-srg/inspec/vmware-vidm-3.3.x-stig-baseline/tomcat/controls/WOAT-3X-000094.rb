control 'WOAT-3X-000094' do
  title 'Workspace ONE Access default servlet must be set to readonly.'
  desc  'The default servlet (or DefaultServlet) is a special servlet provided with Tomcat which is called when no other suitable page is found in a particular folder. The DefaultServlet serves static resources as well as directory listings. The DefaultServlet is configured by default with the "readonly" parameter set to "true" where HTTP commands like PUT and DELETE are rejected. Changing this to false allows clients to delete or modify static resources on the server and to upload new resources. DefaultServlet readonly must be set to true, either literally or by absence (default).'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '/web-app/servlet/servlet-name[text()=\"default\"]/../init-param/param-name[text()=\"readonly\"]/../param-value[text()=\"false\"]' - 2>/dev/null|sed 's/^ *//';done

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

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open each file from the check that contains an unexpected <init-param> in a text editor.

    Find and remove the following block:

    <init-param>
    <param-name>readonly</param-name>
    <param-value>false</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-WOAT-3X-000094'
  tag rid: 'SV-WOAT-3X-000094'
  tag stig_id: 'WOAT-3X-000094'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    describe xml(fname) do
      its('/web-app/servlet[servlet-name="default"]/init-param[param-name="readonly"]/param-value') { should eq [] }
    end
  end
end
