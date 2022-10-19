control 'HZNV-8X-000138' do
  title 'The Horizon Connection Server must enable the Content Security Policy.'
  desc  'The Horizon Connection Server Content Security Policy (CSP) feature mitigates a broad class of content injection vulnerabilities, including cross-site scripting (XSS), clickjacking and other code injection attacks resulting from execution of malicious content in the trusted web page context. The Connection Server defines the policy and the client browser enforces the policy. This feature is enabled by default but must be validated and maintained over time.'
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is not a finding.

    Open the \"locked.properties\" file in a text editor and find the \"enableCSP\" setting.

    If there is no \"enableCSP\" setting, this is not a finding.

    If \"enableCSP\" is present and set to \"false\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Open the \"locked.properties\" file in a text editor.

    Remove the following line:

    enableCSP=false

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000138'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    if !file_content['enableCSP'].nil?
      describe file_content['enableCSP'] do
        it { should_not cmp false }
      end
    else
      describe 'enableCSP property not found in locked.properties file' do
        skip 'no enableCSP property found in locked.properties file'
      end
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found'
    end
  end
end
