control "PHTN-10-000068" do
  title "The Photon operating system must use OpenSSH for remote maintenance
sessions."
  desc  "If the remote connection is not closed and verified as closed, the
session may remain open and be exploited by an attacker; this is referred to as
a zombie session. Remote connections must be disconnected and verified as
disconnected when nonlocal maintenance sessions have been terminated and are no
longer available for use."
  tag severity: nil
  tag gtitle: "SRG-OS-000395-GPOS-00175"
  tag gid: nil
  tag rid: "PHTN-10-000068"
  tag stig_id: "PHTN-10-000068"
  tag fix_id: nil
  tag cci: "CCI-002891"
  tag nist: ["MA-4 (7)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "MA-4 (7)"
  tag check: "At the command line, execute the following command:

# rpm -qa|grep openssh

If there is no output, this is a finding."
  tag fix: "Installing openssh manually is not supported by VMware. Revert to a
previous backup or redeploy the VCSA."

  describe command('rpm -qa|grep openssh') do
    its ('stdout') { should_not eq '' }
  end

end

