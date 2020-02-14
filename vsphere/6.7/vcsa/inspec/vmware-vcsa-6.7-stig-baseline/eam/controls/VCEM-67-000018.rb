control "VCEM-67-000018" do
  title "ESX Agent Manager must fail to a known safe state if system
initialization fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential DoS for users depends on what type of application the web server is
hosting. For the ESX Agent Manager, it is preferable that the service abort
startup on any initialization failure rather than continuing in a degraded, and
potentailly insecure, state."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000225-WSR-000140"
  tag gid: nil
  tag rid: "VCEM-67-000018"
  tag stig_id: "VCEM-67-000018"
  tag cci: "CCI-001190"
  tag nist: ["SC-24", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep EXIT_ON_INIT_FAILURE /etc/vmware-eam/catalina.properties

Expected result :

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open /etc/vmware-eam/catalina.properties

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true"

  describe parse_config_file('/etc/vmware-eam/catalina.properties').params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE'] do
    it { should eq 'true' }
  end

end

