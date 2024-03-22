control 'TCSV-00-000045' do
  title 'The tc Server must encrypt passwords during transmission.'
  desc  "
    Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the tc Server for many reasons.

    Examples include data passed from a user to the tc Server through an HTTPS connection for authentication, the tc Server authenticating to a backend database for data retrieval and posting, and the tc Server authenticating to a clustered web server manager for an update.

    HTTP connections in tc Server are managed through the Connector object. By setting the Connector's “SSLEnabled” flag, SSL handshake/encryption/decryption is enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[not(@SSLEnabled)] | //Connector[@SSLEnabled != 'true']\" $CATALINA_BASE/conf/server.xml

    If no data is returned, this is not a finding.

    For any data returned, if the value of “SSLEnabled” is not set to “true” or is missing for nodes that are configured to use a secure port, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_HOME/server.xml file.

    Navigate to each of the <Connector> nodes that are configured to use a secure port.

    Configure each <Connector> with the value 'SSLEnabled=\"true\"'.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag satisfies: ['SRG-APP-000172-AS-000121']
  tag gid: 'V-TCSV-00-000045'
  tag rid: 'SV-TCSV-00-000045'
  tag stig_id: 'TCSV-00-000045'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # loop through given list of allowed secure ports
  input('securePorts').each do |sp|
    # Get a count of connectors bound to that port
    conn = xmlconf["//*/Connector[@port='#{sp}']/"].count
    if conn > 0
      # If connectors found, check the SSLEnabled setting
      describe "Checking for SSLEnabled on connectors using secure port #{sp}" do
        subject { xmlconf["//*/Connector[@port='#{sp}']/@SSLEnabled"] }
        it { should eq ['true'] }
      end
    else
      describe "Checking for connectors bound to secure port #{sp}" do
        skip "No connectors bound to secure port #{sp}"
      end
    end
  end
end
