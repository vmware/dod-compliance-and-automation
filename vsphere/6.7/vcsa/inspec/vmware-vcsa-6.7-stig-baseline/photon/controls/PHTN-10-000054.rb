control "PHTN-10-000054" do
  title "The Photon operating system must set an inactivity timeout value for
non-interactive sessions."
  desc  "A session time-out is an action taken when a session goes idle for any
reason. Rather than relying on the user to manually disconnect their session
prior to going idle, the Photon operating system must be able to identify when
a session has idled and take action to terminate the session."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000279-GPOS-00109"
  tag gid: nil
  tag rid: "PHTN-10-000054"
  tag stig_id: "PHTN-10-000054"
  tag cci: "CCI-002361"
  tag nist: ["AC-12", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep TMOUT /etc/bash.bashrc

Expected result:

TMOUT=900
readonly TMOUT
export TMOUT

If the file does not exist or the output does not match the expected result,
this is a finding.
"
  desc 'fix', "Open /etc/bash.bashrc with a text editor and set add the following
to the end:

TMOUT=900
readonly TMOUT
export TMOUT"

  describe file('/etc/bash.bashrc') do
    it { should exist }
    its('content') { should match %r{TMOUT=900} }
    its('content') { should match %r{readonly TMOUT} }
    its('content') { should match %r{export TMOUT} }
  end

end

