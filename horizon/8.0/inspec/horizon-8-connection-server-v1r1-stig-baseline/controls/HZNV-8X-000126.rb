control 'HZNV-8X-000126' do
  title 'The Horizon Connection Server must force server cipher preference.'
  desc  "
    By default, during the initial setup of a Transport Layer Security (TLS) connection to the Horizon Connection Server, the client sends a list of supported cipher suites in order of preference. The Connection Server then replies with the cipher suite it will use for communication, chosen from the client list.

    This is not ideal because it allows the untrusted client to set the boundaries and conditions for the connection. The client could potentially specify known weak cipher combinations that would make the communication more susceptible to interception.

    By adding the \"honorClientOrder\" setting to the \"locked.properties\" file, the Connection Server will reject the client preference and force the client to choose from the server ordered list of preferred ciphers.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, confirm with the SA if forcing server-side cipher order was configured at a global level via Group Policy or other means.

    If no such global change was made, this is a finding.

    Open the \"locked.properties\" file in a text editor.

    Find the \"honorClientOrder\" setting and ensure it is set as follows:

    honorClientOrder=false

    If there is no \"honorClientOrder\" setting, or the value of \"honorClientOrder\" is not set to \"false\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Open or create the \"locked.properties\" file in a text editor and add or change the following line:

    honorClientOrder=false

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000126'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    describe file_content['honorClientOrder'] do
      it { should cmp 'false' }
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found - Verify via ADSI EDIT that server-side cipher order is enforced'
    end
  end
end
