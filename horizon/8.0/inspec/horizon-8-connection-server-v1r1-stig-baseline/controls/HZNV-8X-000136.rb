control 'HZNV-8X-000136' do
  title 'The Horizon Connection Server must have X-Frame-Options enabled.'
  desc  "
    The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object> element. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.

    The X-Frame-Options setting is also known as counter clickjacking, and is enabled by default on the Horizon Connection Server. For troubleshooting purposes, it can be disabled by adding the entry \"X-Frame-Options=OFF\" to the \"locked.properties\" file, but this must be avoided when not troubleshooting. The default configuration of enabled must be verified and maintained.

    Note: The 'X-Frame-Options' setting has been obsoleted, for browsers that support it, by the Content-Security-Policy 'frame-ancestors' setting.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is not a finding.

    Open \"locked.properties\" in a text editor and find the \"X-Frame-Options\" setting.

    If there is no \"X-Frame-Options\" setting, this is not a finding.

    If \"X-Frame-Options\" is present and set to \"OFF\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Open the \"locked.properties\" file in a text editor. Remove the following line:

    X-Frame-Options=OFF

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000136'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    if !file_content['X-Frame-Options'].nil?
      describe file_content['X-Frame-Options'] do
        it { should_not cmp 'OFF' }
      end
    else
      describe 'X-Frame-Options property not found in locked.properties file' do
        skip 'no X-Frame-Options property found in locked.properties file'
      end
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found'
    end
  end
end
