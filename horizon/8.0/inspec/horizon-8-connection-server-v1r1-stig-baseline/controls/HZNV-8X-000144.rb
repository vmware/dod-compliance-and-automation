control 'HZNV-8X-000144' do
  title 'The Horizon Connection Server must prevent MIME type sniffing.'
  desc  "
    MIME types define how a given type of file is intended to be processed by the browser. Modern browsers are capable of determining the content type of a file by byte headers and content inspection, allowing the server dictated type to be overridden. An example would be a \".js\" that was sent with a \"jpg\" mime type versus a JavaScript mime type. The browser would normally \"correct\" this and process the file as JavaScript. The danger is that a given file could be disguised as something else on the server, like JavaScript, opening up the door to cross-site scripting.

    To disable browser \"sniffing\" of content type, the Connection Server sends the \"x-content-type-options: nosniff\" header by default. This configuration must be validated and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is not a finding.

    Open the \"locked.properties\" file in a text editor. Find the \"x-content-type-options\" setting.

    If there is no \"x-content-type-options\" setting, this is not a finding.

    If \"x-content-type-options\" is present and set to \"false\", this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\VMware\\VMware View\\Server\\sslgateway\\conf\".

    Open the \"locked.properties\" file in a text editor.

    Remove the following line:

    x-content-type-options=false

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000144'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    if !file_content['x-content-type-options'].nil?
      describe file_content['x-content-type-options'] do
        it { should_not cmp false }
      end
    else
      describe 'x-content-type-options property not found in locked.properties file' do
        skip 'no x-content-type-options property found in locked.properties file'
      end
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found'
    end
  end
end
