control 'VCPF-80-000136' do
  title 'The vCenter Perfcharts service debug parameter must be disabled.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed.

    Because this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed 's/xmlns=\".*\"//g' | xmllint --xpath '//param-name[text()=\"debug\"]/parent::init-param' -

    Example result:

    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
    </init-param>

    If the \"debug\" parameter is specified and is not \"0\", this is a finding.

    If the \"debug\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

    Navigate to all <debug> nodes that are not set to \"0\".

    Set the <param-value> to \"0\" in all <param-name>debug</param-name> nodes.

    Note: The debug setting should look like the following:

    <init-param>
          <param-name>debug</param-name>
          <param-value>0</param-value>
    </init-param>

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCPF-80-000136'
  tag rid: 'SV-VCPF-80-000136'
  tag stig_id: 'VCPF-80-000136'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open web.xml
  xmlconf = xml(input('webXmlPath'))

  describe xmlconf["//init-param[param-name = 'debug']/param-value"] do
    it { should be_in ['', '0'] }
  end
end
