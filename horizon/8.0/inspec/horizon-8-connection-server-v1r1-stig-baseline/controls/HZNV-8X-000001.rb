# -*- encoding : utf-8 -*-
control "HZNV-8X-000001" do
  title "The Horizon Connection Server must limit the number of concurrent client sessions."
  desc  "
    The Horizon Connection Server has the ability to limit the number of simultaneous client connections. This capability is helpful in limiting resource exhaustion risks related to denial of service attacks. By default, the Connection Server allows up to 2000 client connections at one time, over all protocol types. For larger deployments, this limit can be increased to a tested and supported maximum of 4000 by making modifications to the \"locked.properties\" file.
    
    Note: Ensure any changes to the number of allowed simultaneous connections is supported by VMware for the choice of protocols and that this value is documented as part of the SSP.
  "
  desc  "rationale", ""
  desc  "check", "
    If the \"HTTP(S) Secure Tunnel\" option is not enabled in the Connection Server configuration, this control is not applicable.
    
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".
    
    If a file named \"locked.properties\" does not exist in this path, this is not a finding.
    
    Open \"locked.properties\" in a text editor.
    
    The \"maxConnections\" setting may be set higher than the default of \"2000\" (up to a maximum of 4000) to support larger Horizon deployments.
    
    If there is no \"maxConnections\" setting, this is not a finding.
    
    If \"maxConnections\" is set to more than \"4000\", this is a finding.
    
    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  desc  "fix", "
    If the \"HTTP(S) Secure Tunnel\" option is enabled in the Connection Server configuration, perform the following actions if the default value of 2000 is insufficient.
    
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".
    
    Open the \"locked.properties\" file in a text editor, or create it if not there. Add or change the following line:
    
    maxConnections=2000
    
    The default value of \"2000\" may be increased to no more than 4000 if required and properly documented. Otherwise, keep the default value of \"2000\".
    
    Save and close the file. Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
    
    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000001-AS-000001"
  tag satisfies: ["SRG-APP-000435-AS-000163"]
  tag gid: "V-HZNV-8X-000001"
  tag rid: "SV-HZNV-8X-000001"
  tag stig_id: "HZNV-8X-000001"
  tag cci: ["CCI-000054", "CCI-002385"]
  tag nist: ["AC-10", "SC-5"]
  
  horizonhelper.setconnection
  
  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    if !file_content['maxConnections'].nil?
      describe file_content['maxConnections'] do
        it { should cmp <= 4000 }
      end
    else
      describe 'maxConnections property not found in locked.properties file' do
        skip 'no maxConnections property found in locked.properties file'
      end
    end
  else
    describe 'locked.properties file not found in provided location' do
      skip 'locked.properties file not found'
    end
  end
end