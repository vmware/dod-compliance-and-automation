control 'V-219211' do
  title "The Ubuntu Operating system must disable the x86 Ctrl-Alt-Delete key sequence if a
    graphical user interface is installed."
  desc  "A locally logged-on user who presses Ctrl-Alt-Delete, when at the console,
    can reboot the system. If accidentally pressed, as could happen in the case of a mixed
    OS environment, this can create the risk of short-term loss of availability of systems
    due to unintentional reboot. In the graphical environment, risk of unintentional reboot
    from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any
    action is taken.
  "

  impact 0.8
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": 'V-219211'
  tag "rid": "SV-219211r388482_rule"
  tag "stig_id": "UBTU-18-010150"
  tag "fix_id": "F-20935r304962_fix"
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
    when Ctrl-Alt-Delete is pressed when using a graphical user interface.

    Check that the \"logout\" target is not bound to an action with the following command:

    # grep logout /etc/dconf/db/local.d/*

    logout=''

    If the \"logout\" key is bound to an action, is commented out, or is missing, this is a finding.
  "
  desc 'fix', "Configure the system to disable the Ctrl-Alt-Delete sequence when using a
    graphical user interface by creating or editing the /etc/dconf/db/local.d/00-disable-CAD
    file.

    Add the setting to disable the Ctrl-Alt-Delete sequence for the graphical user interface:

    [org/gnome/settings-daemon/plugins/media-keys]
    logout=''

    Then update the dconf settings:

    # dconf update
  "
  describe 'Not Applicable' do
    skip 'GUI'
  end
end
