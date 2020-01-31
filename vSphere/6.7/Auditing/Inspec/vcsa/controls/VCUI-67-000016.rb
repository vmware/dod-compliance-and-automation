control "VCUI-67-000016" do
  title "vSphere UI directory tree must have permissions in an \"out of the
box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. The vSphere
UI files must be adequately protected with correct permissions as applied \"out
of the box\"."
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000016"
  tag stig_id: "VCUI-67-000016"
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
  tag check: "At the command prompt, execute the following command:

# find /usr/lib/vmware-vsphere-ui/server/lib
/usr/lib/vmware-vsphere-ui/server/conf -xdev -type f -a '(' -perm -o+w -o -not
-user vsphere-ui -o -not -group root ')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  tag fix: "At the command prompt, execute the following command:


# chmod o-w <file>

# chown vsphere-ui:root <file>

Repeat the command for each file that was returned
"
end

