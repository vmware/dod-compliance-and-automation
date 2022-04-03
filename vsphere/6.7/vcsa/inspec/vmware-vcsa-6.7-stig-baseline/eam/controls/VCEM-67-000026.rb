control 'VCEM-67-000026' do
  title 'ESX Agent Manager must have the debug option turned off.'
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server
and plug-ins or modules being used. When debugging or trace information is
enabled in a production web server, information about the web server, such as
web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage may be displayed.

    Because this information may be placed in logs and general messages during
normal operation of the web server, an attacker does not need to cause an error
condition to gain this information.

    ESX Agent Manager can be configured to set the debugging level. By setting
the debugging level to zero (0), no debugging information will be provided to a
malicious user.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    #  xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml |
sed 's/xmlns=\".*\"//g' | xmllint --xpath
'//param-name[text()=\"debug\"]/parent::init-param' -
    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
        </init-param>

    Expected result:

    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
    </init-param>

    If the output does not match the expected result, this is a finding.

    If no lines are returned, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

    Navigate to all <debug> nodes that are not set to \"0\".

    Set the <param-value> to \"0\" in all <param-name>debug</param-name> nodes.

    Note: The debug setting should look like the following:

    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
    </init-param>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-239397'
  tag rid: 'SV-239397r717099_rule'
  tag stig_id: 'VCEM-67-000026'
  tag fix_id: 'F-42589r717098_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe.one do
    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should eq [] }
    end

    describe xml("#{input('webXmlPath')}") do
      its('/web-app/servlet/init-param[param-name="debug"]/param-value') { should cmp '0' }
    end
  end
end
