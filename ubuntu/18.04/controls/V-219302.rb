control 'V-219302' do
  title "The Ubuntu operating system must retain a users session lock until that user
    reestablishes access using established identification and authentication procedures."
  desc  "A session lock is a temporary action taken when a user stops work and moves
  away from the immediate physical vicinity of the information system but does not want
  to log out because of the temporary nature of the absence.

  The session lock is implemented at the point where session activity can be determined.
  Rather than be forced to wait for a period of time to expire before the user session can be
  locked, Ubuntu operating systems need to provide users with the ability to manually invoke a
  session lock so users may secure their session should the need arise for them to temporarily
  vacate the immediate physical vicinity."

  impact 0.5
  tag "gtitle": "SRG-OS-000028-GPOS-00009"
  tag "gid": 'V-219302'
  tag "rid": "SV-219302r378535_rule"
  tag "stig_id": "UBTU-18-010401"
  tag "fix_id": "F-21026r305235_fix"
  tag "cci": [ "CCI-000056" ]
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
  desc 'check', "Verify the Ubuntu operation system has a graphical user interface
    session lock enabled.

    Note: If the Ubuntu operating system does not have a Graphical User Interface installed,
    this requirement is Not Applicable.

    Get the \"\"lock-enabled\"\" setting to verify if the graphical user interface session has
    the lock enabled with the following command:

    # sudo gsettings get org.gnome.desktop.screensaver lock-enabled

    true

    If \"lock-enabled\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system so that it allows a user to lock the current
    graphical user interface session.

    Note: If the Ubuntu operating system does not have a Graphical User Interface installed, this
    requirement is Not Applicable.

    Set the \"\"lock-enabled\"\" setting to allow graphical user interface session locks with
    the following command:

    # sudo gsettings set org.gnome.desktop.screensaver lock-enabled true
  "
  describe 'Not Applicable' do
    skip 'GUI'
  end
end
