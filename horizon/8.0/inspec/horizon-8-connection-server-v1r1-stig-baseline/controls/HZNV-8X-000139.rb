control 'HZNV-8X-000139' do
  title ' The Horizon Connection Server must enable the proper Content Security Policy directives.'
  desc  'The Horizon Connection Server Content Security Policy (CSP) feature mitigates a broad class of content injection vulnerabilities including cross-site scripting (XSS), clickjacking and other code injection attacks resulting from execution of malicious content in the trusted web page context. The Connection Server has default CSP directives that block XSS attacks, enable x-frame restrictions, and more. If the default configurations are overridden, the protections may be disabled even though the CSP itself is still enabled. This default policy must be validated and maintained over time.'
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is not a finding.

    Open the \"locked.properties\" file in a text editor.

    If any settings containing the text \"content-security-policy\" are present, this is a finding.

    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  desc 'fix', "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".

    If a file named \"locked.properties\" does not exist in this path, this is not a finding.

    Open the \"locked.properties\" file in a text editor. Find and remove any settings matching the following pattern, if present:

    content-security-policy*

    Save and close the file.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.

    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-HZNV-8X-000139'
  tag rid: 'SV-HZNV-8X-000139'
  tag stig_id: 'HZNV-8X-000139'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    describe file_content do
      its('content-security-policy') { should cmp nil }
      its('content-security-policy-newadmin') { should cmp nil }
      its('content-security-policy-portal') { should cmp nil }
      its('content-security-policy-rest') { should cmp nil }
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found'
    end
  end
end
