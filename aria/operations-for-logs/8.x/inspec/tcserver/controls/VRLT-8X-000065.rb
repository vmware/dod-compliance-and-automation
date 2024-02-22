control 'VRLT-8X-000065' do
  title 'The VMware Aria Operations for Logs tc Server must set URIEncoding to UTF-8.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

    To mitigate against many types of character-based vulnerabilities, tc Server should be configured to use a consistent character set. The URIEncoding attribute on the Connector nodes provides the means for tc Server to enforce a consistent character set encoding.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[not(@URIEncoding)] | //Connector[@URIEncoding != 'UTF-8']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml | awk 1 RS='<Connector' ORS='\
    <Connector'

    If the value of \"URIEncoding\" is not set to \"UTF-8\" or is missing for each connector item returned, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value 'URIEncoding=\"UTF-8\"'.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-VRLT-8X-000065'
  tag rid: 'SV-VRLT-8X-000065'
  tag stig_id: 'VRLT-8X-000065'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  describe xmlconf do
    its(["name(//Connector[not(@URIEncoding)] | //Connector[@URIEncoding != 'UTF-8'])"]) { should cmp [] }
  end
end
