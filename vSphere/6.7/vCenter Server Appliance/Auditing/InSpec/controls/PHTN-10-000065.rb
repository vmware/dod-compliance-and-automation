control "PHTN-10-000065" do
  title "The Photon operating system must require users to re-authenticate for
privilege escalation."
  desc  "Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user re-authenticate.
  "
  tag severity: nil
  tag gtitle: "SRG-OS-000373-GPOS-00156"
  tag gid: nil
  tag rid: "PHTN-10-000065"
  tag stig_id: "PHTN-10-000065"
  tag fix_id: nil
  tag cci: "CCI-002038"
  tag nist: ["IA-11", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "IA-11"
  tag check: "Check the configuration of the \"/etc/sudoers\" and
\"/etc/sudoers.d/*\" files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any account listed in the output has a password hash in /etc/shadow, this is
a finding."
  tag fix: "Check the configuration of the \"/etc/sudoers\" and
\"/etc/sudoers.d/*\" files with the following command:

# visudo
OR
# visudo -f /etc/sudoers.d/<file name>

Remove any occurrences of \"NOPASSWD\" tags associated with user accounts with
a password hash."

  #Find users in sudoers with NOPASSWD flag and extract username
  results = command("awk '/NOPASSWD/ && /^[^#%].*/ {print $1}' /etc/sudoers").stdout.split("\n")
  
  #Compare results to shadow file to verify their password is set to !
  results.each do | result |
    describe shadow.where(password: '!') do
      its('users') { should include (result) }
    end
  end

end

