control 'V-219303' do
  title "The Ubuntu operating system must initiate a session lock after a 15-minute period of
    inactivity for all connection types."
  desc  "An Ubuntu operating system needs to be able to identify when a user's
    sessions has idled for longer than 15 minutes. The Ubuntu operating system must
    logout a users' session after 15 minutes to prevent anyone from gaining access
    to the machine while the user is away.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": 'V-219303'
  tag "rid": "SV-219303r378598_rule"
  tag "stig_id": "UBTU-18-010402"
  tag "fix_id": "F-21027r305238_fix"
  tag "cci": [ "CCI-000057" ]
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
  desc 'check', "Verify the Ubuntu operating system initiates a session logout after a
  15-minute period of inactivity.

    Check that the proper auto logout script exists with the following command:

    # cat /etc/profile.d/autologout.sh
    TMOUT=900
    readonly TMOUT
    export TMOUT

    If the file \"/etc/profile.d/autologout.sh\" does not exist with the contents shown above,
    the value of \"TMOUT\" is greater than 900, or the timeout values are commented out, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to initiate a session logout after a
    15-minute period of inactivity.

    Create a file to contain the system-wide session auto logout script (if it does not
    already exist) with the following command:

    # sudo touch /etc/profile.d/autologout.sh

    Add the following lines to the \"/etc/profile.d/autologout.sh\" script:

    TMOUT=900
    readonly TMOUT
    export TMOUT
  "
  describe file('/etc/profile.d/autologout.sh') do
    it { should exist }
    its('content') { should match /^\s*TMOUT=900\s*$/ }
    its('content') { should match /^\s*readonly\s+TMOUT\s*$/ }
    its('content') { should match /^\s*export\s+TMOUT\s*$/ }
  end
end
