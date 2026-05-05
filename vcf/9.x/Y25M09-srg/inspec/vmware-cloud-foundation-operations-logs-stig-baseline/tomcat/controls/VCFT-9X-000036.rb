control 'VCFT-9X-000036' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must disable stack tracing.'
  desc  'Stack tracing provides debugging information from the application call stacks when a runtime error is encountered. If stack tracing is left enabled, tc Server will provide this call stack information to the requestor which could result in the loss of sensitive information or data that could be used to compromise the system. '
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[@allowTrace]\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    XPath set is empty

    If any connector element contains the 'allowTrace = \"true\"' statement, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Remove the 'allowTrace=\"true\"' setting from any connector objects where it is present.

    Note: If \"allowTrace\" is not present, it defaults to \"false\".

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCFT-9X-000036'
  tag rid: 'SV-VCFT-9X-000036'
  tag stig_id: 'VCFT-9X-000036'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # allowTrace either shouldn't be present, or if it is, it should be false
  describe xmlconf do
    its(["//Connector[@allowTrace != 'false']/@port | //Connector[not[@allowTrace]]/@port"]) { should cmp [] }
  end
end
