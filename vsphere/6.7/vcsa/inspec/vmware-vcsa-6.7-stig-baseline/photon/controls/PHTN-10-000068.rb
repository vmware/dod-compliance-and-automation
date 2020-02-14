control "PHTN-10-000068" do
  title "The Photon operating system must use OpenSSH for remote maintenance
sessions."
  desc  "If the remote connection is not closed and verified as closed, the
session may remain open and be exploited by an attacker; this is referred to as
a zombie session. Remote connections must be disconnected and verified as
disconnected when nonlocal maintenance sessions have been terminated and are no
longer available for use."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000395-GPOS-00175"
  tag gid: nil
  tag rid: "PHTN-10-000068"
  tag stig_id: "PHTN-10-000068"
  tag cci: "CCI-002891"
  tag nist: ["MA-4 (7)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# rpm -qa|grep openssh

If there is no output, this is a finding."
  desc 'fix', "Installing openssh manually is not supported by VMware. Revert to a
previous backup or redeploy the VCSA."

  describe command('rpm -qa|grep openssh') do
    its ('stdout') { should_not eq '' }
  end

end

