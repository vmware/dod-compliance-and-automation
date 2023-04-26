control 'HZNV-8X-000126' do
  title 'The Horizon Connection Server must force server cipher preference.'
  desc  "
    By default, during the initial setup of a Transport Layer Security (TLS) connection to the Horizon Connection Server, the client sends a list of supported cipher suites in order of preference. The Connection Server then replies with the cipher suite it will use for communication, chosen from the client list.

    This is not ideal because it allows the untrusted client to set the boundaries and conditions for the connection. The client could potentially specify known weak cipher combinations that would make the communication more susceptible to interception.

    By adding the \"honorClientOrder\" setting to the \"locked.properties\" file, the Connection Server will reject the client preference and force the client to choose from the server ordered list of preferred ciphers.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".

    If a file named \"locked.properties\" exists in this path, open the file in a text editor.

    If the \"locked.properties\" file contains an entry for \"honorClientOrder\", ensure the value is set as follows:

    honorClientOrder=false

    If the \"honorClientOrder\" value is not set exactly as above, this is a finding.

    If no \"locked.properties\" file exists, open the \"config.properties\" file in a text editor.

    Ensure the value for \"honorClientOrder\" is set as follows:

    honorClientOrder=false

    If there is no \"honorClientOrder\" setting, or the value of \"honorClientOrder\" is not set to \"false\", this is a finding.

    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".

    Open or create the \"locked.properties\" file in a text editor and add or change the following line:

    honorClientOrder=false

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.

    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag gid: 'V-HZNV-8X-000126'
  tag rid: 'SV-HZNV-8X-000126'
  tag stig_id: 'HZNV-8X-000126'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  horizonhelper.setconnection

  # check in following order:
  # 1. locked.properties exist? if so, does it contain value?
  # 2. if "no" to either question, check "config.properties", value should be there.

  honorFound = false

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    locked_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")

    unless locked_content['honorClientOrder'].nil?
      honorFound = true
      describe 'Checking locked.properties for honorClientOrder' do
        subject { locked_content['honorClientOrder'] }
        it { should cmp 'false' }
      end
    end

  end

  unless honorFound
    config_content = parse_config_file("#{input('sslConfFolderPath')}\\config.properties")

    describe 'Checking config.properties for honorClientOrder' do
      subject { config_content['honorClientOrder'] }
      it { should cmp 'false' }
    end

  end
end
