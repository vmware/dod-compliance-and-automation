control "PHTN-10-000120" do
  title "The Photon operating system must protect all sysctl configuration
files from unauthorized access."
  desc  "The sysctl configuration file specify  values for kernel parameters to
be set on boot. Incorrect or malicious configuration of these parameters can
have a negative effect on system security."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000120"
  tag stig_id: "PHTN-10-000120"
  tag fix_id: nil
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-6 b"
  tag check: "At the command line, execute the following command:

# find /etc/sysctl.conf /etc/sysctl.d/* -xdev -type f -a '(' -not -perm 600 -o
-not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  tag fix: "At the command line, execute the following commands for each
returned file:

# chmod 600 <file>
# chown root:root <file>"

  describe command("find /etc/sysctl.conf /etc/sysctl.d/* -xdev -type f -a '(' -not -perm 600 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
     its ('stdout') { should eq '' }
  end

end

