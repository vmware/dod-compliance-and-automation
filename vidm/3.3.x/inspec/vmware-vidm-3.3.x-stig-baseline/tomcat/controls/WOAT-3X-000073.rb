control 'WOAT-3X-000073' do
  title 'Workspace ONE Access must have the debug option turned off.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.

    Workspace ONE Access can be configured to set the debugging level. By setting the debugging level to zero (0), no debugging information will be provided to a malicious user.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # for xml in $(find /opt/vmware/horizon/workspace/ -name web.xml); do echo $xml; xmllint --format $xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '//param-name[text()=\"debug\"]/..' - 2>/dev/null|sed 's/^ *//';done

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
    <param-name>debug</param-name>
    <param-value>0</param-value>
    </init-param>

    If the output does not match the expected result, this is a finding.

    If no '<init-param>' blocks are returned, this is NOT a finding.
  "
  desc 'fix', "
    Open each file from the check that contains an unexpected or incorrect <init-param> in a text editor.

    Only /opt/vmware/horizon/workspace/conf/web.xml should have a <init-param> entry, as shown below:

    <init-param>
    <param-name>debug</param-name>
    <param-value>0</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-WOAT-3X-000073'
  tag rid: 'SV-WOAT-3X-000073'
  tag stig_id: 'WOAT-3X-000073'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  command('find /opt/vmware/horizon/workspace/ -name web.xml').stdout.split.each do |fname|
    if fname == '/opt/vmware/horizon/workspace/conf/web.xml'
      describe.one do
        describe xml(fname) do
          its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should eq [] }
        end

        describe xml(fname) do
          its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should cmp '0' }
        end
      end
    else
      describe xml(fname) do
        its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should eq [] }
      end
    end
  end
end
