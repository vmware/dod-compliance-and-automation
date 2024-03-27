control 'TCSV-00-000134' do
  title 'The shutdown port must be disabled.'
  desc  'tc Server by default listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within tc Server are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Setting the port to "-1" instructs tc Server to not listen for the shutdown command.'
  desc  'rationale', ''
  desc  'check', "
    To check the shutdown port, at the command prompt, run the following command:

    # grep \"base.shutdown.port\" $CATALINA_BASE/conf/catalina.properties

    Expected output:

    base.shutdown.port=-1

    To check the shutdown command, at the command prompt, run the following command:

    # xmllint --xpath \"//Server/@port | //Server/@shutdown\" $CATALINA_BASE/conf/server.xml

    Expected output should include:

    shutdown=\"NONDETERMINISTICVALUE\"

    If the shutdown port is not set to \"-1\" and/or the shutdown command equals \"SHUTDOWN\", this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/catalina.properties file.

    Add or edit the following line:

    base.shutdown.port=-1

    Edit the $CATALINA_HOME/server.xml file.

    Set the shutdown command value in the Server node.

    EXAMPLE:
    <Server shutdown=\"NONDETERMINISTICVALUE\">

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-TCSV-00-000134'
  tag rid: 'SV-TCSV-00-000134'
  tag stig_id: 'TCSV-00-000134'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content)
  sp = input('shutdownPort')

  describe props do
    its(['base.shutdown.port']) { should cmp sp }
  end

  describe xml("#{input('catalinaBase')}/conf/server.xml") do
    its(['/Server/@shutdown']) { should_not cmp ['SHUTDOWN'] }
  end
end
