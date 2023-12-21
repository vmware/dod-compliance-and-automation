control 'TCSV-00-000051' do
  title 'tc Server must use FIPS-validated ciphers on secured connectors.'
  desc  "
    Connectors are how tc Server receives requests over a network port, passes them to hosted web applications via HTTP or AJP, and then sends the results back to the requestor. Cryptographic ciphers are associated with the connector to create a secured connector. To ensure encryption strength is adequately maintained, the ciphers used must be FIPS 140-2-validated.

    The FIPS-validated crypto libraries are not provided by tc Server; they are included as part of the Java instance and the underlying Operating System. The STIG checks to ensure the FIPSMode setting is enabled for the connector and also checks the logs for FIPS errors, which indicates FIPS non-compliance at the OS or Java layers. The administrator is responsible for ensuring the OS and Java instance selected for the tc Server installation provide and enable these FIPS modules so tc Server can be configured to use them.
  "
  desc  'rationale', ''
  desc  'check', "
    From the server console, run the following two commands to verify tc Server is configured to use FIPS:

    sudo grep -i FIPSMode $CATALINA_BASE/conf/server.xml

    sudo grep -i FIPSMode $CATALINA_BASE/logs/catalina.out

    If server.xml does not contain FIPSMode=\"on\", or if catalina.out does not contain the message \"Successfully entered FIPS mode\", this is a finding.
  "
  desc 'fix', "
    In addition to configuring tc Server, the administrator must also configure the underlying OS and Java engine to use FIPS validated encryption modules. This fix instructs how to enable FIPSMode within tc Server. The OS and Java engine must be configured to use the FIPS validated modules according to the chosen OS and Java engine.

    Navigate to and open $CATALINA_HOME/server.xml.

    In the list of <Listener> elements, locate the AprLifecycleListener. Add or edit the FIPSMode setting and set it to FIPSMode=\"on\".

    EXAMPLE:
    <Listener
          className=\"org.apache.catalina.core.AprLifecycleListener\"
          SSLEngine=\"on\"
          FIPSMode=\"on\"
    />

    Restart the Tomcat server:
    #sudo systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag satisfies: ['SRG-APP-000439-AS-000274']
  tag gid: 'V-TCSV-00-000051'
  tag rid: 'SV-TCSV-00-000051'
  tag stig_id: 'TCSV-00-000051'
  tag cci: %w(CCI-000803 CCI-002418)
  tag nist: %w(IA-7 SC-8)

  # Get path to server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # Check for a Listener Element
  describe xmlconf['//Listener[contains(@className, "AprLifecycleListener")]/@FIPSMode'] do
    it { should eq ['on'] }
  end

  # Check catalina log for FIPS success
  if file("#{input('catalinaHome')}/logs/catalina.out").exist?
    describe 'Checking catalina log for FIPS Mode enabled' do
      subject { file("#{input('catalinaHome')}/logs/catalina.out").content }
      it { should include('Successfully entered FIPS mode') }
    end
  else
    describe 'Catalina.out log file not found in default location' do
      skip 'Catalina.out log file not found'
    end
  end
end
