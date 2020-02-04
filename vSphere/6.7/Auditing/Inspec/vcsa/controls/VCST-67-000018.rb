control "VCST-67-000018" do
  title "The Security Token Service must fail to a known safe state if system
initialization fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential DoS for users depends on what type of application the web server is
hosting. For the Security Token Service, it is preferable that the service
abort startup on any initialization failure rather than continuing in a
degraded, and potentailly insecure, state."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000225-WSR-000140"
  tag gid: nil
  tag rid: "VCST-67-000018"
  tag stig_id: "VCST-67-000018"
  tag fix_id: nil
  tag cci: "CCI-001190"
  tag nist: ["SC-24", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SC-24"
  tag check: "At the command line, execute the following command:

# grep EXIT_ON_INIT_FAILURE
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Expected result :

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If the output of the command does not match the expected result, this is a
finding."
  tag fix: "Navigate to and open
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true"
end

