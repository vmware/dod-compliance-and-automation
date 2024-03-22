control 'VRLT-8X-000135' do
  title 'The VMware Aria Operations for Logs tc Server must disable unapproved connectors.'
  desc  "
    Connectors are how tc Server receives requests, passes them to hosted web applications, and then sends back the results to the requestor. Tomcat provides HTTP and Apache JServ Protocol (AJP) connectors and makes these protocols available via configured network ports. Unapproved connectors provide open network connections to either of these protocols and put the system at risk.

    Review the SSP for the list of approved connectors and associated TCP/IP ports and ensure only approved connectors are present.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[not(@redirectPort)]/@port\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml | awk 1 RS=' ' ORS='\
    '

    Review the results and verify all connectors that are not redirects and their associated network ports are approved in the SSP.

    If connectors are found but are not approved in the SSP, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Remove any unapproved connectors.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000135'
  tag rid: 'SV-VRLT-8X-000135'
  tag stig_id: 'VRLT-8X-000135'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # Find connectors that are not redirects
  xmlconf['//Connector[not(@redirectPort)]/@port'].each do |port|
    describe port do
      it { should be_in input('approvedConnectorPorts') }
    end
  end
end
