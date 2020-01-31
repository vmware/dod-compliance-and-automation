control "VCUI-67-000017" do
  title "vSphere UI must fail to a known safe state if system initialization
fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential DoS for users depends on what type of application the web server is
hosting. For the Security Token Service, it is preferable that the service
abort startup on any initialization failure rather than continuing in a
degraded, and potentailly insecure, state."
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000017"
  tag stig_id: "VCUI-67-000017"
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  tag check: "At the command line, execute the following command:

# grep EXIT_ON_INIT_FAILURE
/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

Expected result :

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If the output of the command does not match the expected result, this is a
finding."
  tag fix: "Navigate to and open /etc/vmware-eam/catalina.properties

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true"
end

