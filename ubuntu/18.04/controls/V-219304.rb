control 'V-219304' do
  title "The Ubuntu operating system must be configured for users to directly initiate
    a session lock for all connection types."
  desc  "A session lock is a temporary action taken when a user stops work and
    moves away from the immediate physical vicinity of the information system but
    not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
    determined. Rather than be forced to wait for a period of time to expire before
    the user session can be locked, Ubuntu operating systems need to provide users
    with the ability to manually invoke a session lock so users may secure their
    session should the need arise for them to temporarily vacate the immediate
    physical vicinity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000030-GPOS-00011"
  tag "satisfies": nil
  tag "gid": 'V-219304'
  tag "rid": "SV-219304r378601_rule"
  tag "stig_id": "UBTU-18-010403"
  tag "fix_id": "F-21028r305241_fix"
  tag "cci": [ "CCI-000058","CCI-000060" ]
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
  desc 'check', "Verify the Ubuntu operating system has the 'vlock' package
    installed, by running the following command:

    # dpkg -l | grep vlock

    If \"vlock\" is not installed, this is a finding.
  "
  desc 'fix', "Install the \"vlock\" (if it is not already installed) package
    by running the following command:

    # sudo apt-get install vlock
  "
  describe package('vlock') do
    it { should be_installed }
  end
end
