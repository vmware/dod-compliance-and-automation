control "VCST-67-000017" do
  title "The Security Token Service directory tree must have permissions in an
\"out of the box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. The
Security Token Service files must be adequately protected with correct
permissions as applied \"out of the box\"."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000211-WSR-000030"
  tag gid: nil
  tag rid: "VCST-67-000017"
  tag stig_id: "VCST-67-000017"
  tag fix_id: nil
  tag cci: "CCI-001082"
  tag nist: ["SC-2", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SC-2"
  tag check: "At the command prompt, execute the following command:

# find /usr/lib/vmware-sso/vmware-sts/ -xdev -type f -a '(' -not -user root -o
-not -group root ')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  tag fix: "At the command prompt, execute the following command:

# chown\ root:root <file_name>

Repeat the command for each file that was returned

Note: Replace <file_name> for the name of the file that was returned.
"

  describe command('find /usr/lib/vmware-sso/vmware-sts/ -xdev -type f -a \'(\' -not -user root -o -not -group root \')\' -exec ls -ld {} \;') do
   its('stdout.strip') { should eq ''}
  end

end