control 'V-219212' do
  title 'The Ubuntu Operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc  "A locally logged-on user who presses Ctrl-Alt-Delete, when at the
    console, can reboot the system. If accidentally pressed, as could happen in the
    case of a mixed OS environment, this can create the risk of short-term loss of
    availability of systems due to unintentional reboot. In the GNOME graphical
    environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
    reduced because the user will be prompted before any action is taken.
  "
  impact 0.8
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": 'V-219212'
  tag "rid": "SV-219212r388482_rule"
  tag "stig_id": "UBTU-18-010151"
  tag "fix_id": "F-20936r304965_fix"
  tag "cci": [ "CCI-000366" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the Ubuntu operating system is not configured to reboot the system
    when Ctrl-Alt-Delete is pressed.

    Check that the \"ctrl-alt-del.target\" (otherwise also known as reboot.target) is not
    active with the following command:

    # systemctl status ctrl-alt-del.target
    reboot.target - Reboot
    Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
    Active: inactive (dead)
    Docs: man:systemd.special(7)

    If the \"ctrl-alt-del.target\" is active, this is a finding.
  "

  desc 'fix', "Configure the system to disable the Ctrl-Alt-Delete sequence for the command
    line with the following command:

    # sudo systemctl mask ctrl-alt-del.target

    And reload the daemon to take effect

    # sudo systemctl daemon-reload
  "

  describe service('ctrl-alt-del.target') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end
