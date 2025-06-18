control 'VCFT-9X-000065' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must set URIEncoding to UTF-8.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

    To mitigate against many types of character-based vulnerabilities, the server should be configured to use a consistent character set. The URIEncoding attribute on the Connector nodes provides the means to enforce a consistent character set encoding.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    XPath set is empty

    If any connectors are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value 'URIEncoding=\"UTF-8\"'.

    Note: If \"URIEncoding\" is not present, it defaults to \"UTF-8\".

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-VCFT-9X-000065'
  tag rid: 'SV-VCFT-9X-000065'
  tag stig_id: 'VCFT-9X-000065'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  describe xmlconf do
    its(["name(//Connector[not(@URIEncoding)] | //Connector[@URIEncoding != 'UTF-8'])"]) { should cmp [] }
  end
end
