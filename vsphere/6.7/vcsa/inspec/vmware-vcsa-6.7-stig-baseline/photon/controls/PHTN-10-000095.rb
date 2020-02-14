control "PHTN-10-000095" do
  title "The Photon operating system must be configured so that the x86
Ctrl-Alt-Delete key sequence is disabled on the command line."
  desc  "When the Ctrl-Alt-Del target is enabled, locally logged-on user who
presses Ctrl-Alt-Delete, when at the console, can reboot the system. If
accidentally pressed, as could happen in the case of a mixed OS environment,
this can create the risk of short-term loss of availability of systems due to
unintentional reboot. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000095"
  tag stig_id: "PHTN-10-000095"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# systemctl status ctrl-alt-del.target

Expected result:

ctrl-alt-del.target
Loaded: masked (/dev/null; bad)
Active: inactive (dead)

If the output does not match the expected result, this is a finding"
  desc 'fix', "At the command line, execute the following command:

# systemctl mask ctrl-alt-del.target"

  describe systemd_service('ctrl-alt-del.target') do
    it { should_not be_enabled}
    it { should_not be_running}
  end

end

