# -*- encoding : utf-8 -*-
control "HZNV-8X-000137" do
  title "The Horizon Connection Server must have Origin Checking enabled."
  desc  "
    RFC 6454 Origin Checking, which protects against cross-site request forging, is enabled by default on the Horizon Connection Server. When an administrator opens the Horizon Console or a user connects to Blast HTML Access, the server checks that the origin URL for the web request matches either the configured secure tunnel URL or \"localhost\".
    
    When the Connection Server is load balanced or front-ended by a Unified Access Gateway (UAG) appliance, origin checking will fail. This is commonly resolved by disabling origin checking entirely by specifying \"checkOrigin=false\" in the \"locked.properties\" file. This is not the proper solution. Instead, origin checking must be enabled and the load balancer and UAG appliances must be allow listed via the \"balancedHost\" and \"portalHost.X\" settings in \"locked.properties\", respectively.
    
    Additionally, the \"locked.properties\" should contain a setting for \"allowUnexpectedHost=false\". This setting currently defaults to \"true\", and must be explicitly set to \"false\" to cause requests to be rejected if the Host header does not match an entry on the allow list.
    
    Origin checking can be disabled by adding the entry \"checkOrigin=false\" to \"locked.properties\", usually for troubleshooting purposes. The default, \"checkOrigin=true\" or unspecified configuration must be verified and maintained.
  "
  desc  "rationale", ""
  desc  "check", "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".
    
    If a file named \"locked.properties\" does not exist in this path, this is a finding.
    
    Open the \"locked.properties\" file and find the \"allowUnexpectedHost\" setting.
    
    If there is no \"allowUnexpectedHost\" setting, this is a finding.
    
    If \"allowUnexpectedHost\" is present and set to \"true\", this is a finding.
    
    Find the \"checkOrigin\" setting.
    
    If there is no \"checkOrigin\" setting, this is not a finding.
    
    If \"checkOrigin\" is present and set to \"false\", this is a finding.
    
    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  desc  "fix", "
    On the Horizon Connection Server, navigate to \"<install_directory>\\sslgateway\\conf\".
    
    Open the \"locked.properties\" file in a text editor.
    
    Add or edit the following line:
    
    allowUnexpectedHost=false
    
    Remove the following line if present:
    
    checkOrigin=false
    
    To allow list a load balancer in front of the Connection Server, add the following line:
    
    balancedHost=<load-balancer-name-here>
    
    To allow list Unified Access Gateway (UAG) gateways, add every address using the following format and pattern:
    
    portalHost.1=<access-point-name-1>
    portalHost.2=<access-point-name-2>
    ...
    
    Save and close the file.
    
    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
    
    NOTE: \"<install_directory>\" defaults to \"%PROGRAMFILES%\\VMware\\VMware View\\Server\\\" unless changed during install.
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000516-AS-000237"
  tag gid: "V-HZNV-8X-000137"
  tag rid: "SV-HZNV-8X-000137"
  tag stig_id: "HZNV-8X-000137"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
  
  horizonhelper.setconnection
  
  if file("#{input('sslConfFolderPath')}\\locked.properties").exist?
    file_content = parse_config_file("#{input('sslConfFolderPath')}\\locked.properties")
    if !file_content['checkOrigin'].nil?
      describe file_content['checkOrigin'] do
        it { should_not cmp 'OFF' }
      end
    else
      describe 'checkOrigin property not found in locked.properties file' do
        skip 'no checkOrigin property found in locked.properties file'
      end
    end
  
    describe 'checking allowUnexpectedHost setting' do
      subject { file_content['allowUnexpectedHost'] }
      it { should cmp 'false' }
    end
  else
    describe file("#{input('sslConfFolderPath')}\\locked.properties") do
      it { should exist }
    end
  end
end