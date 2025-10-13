control 'PHTN-50-000093' do
  title 'The operating system must automatically terminate a user session after inactivity time-outs have expired.'
  desc  "
    Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

    Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

    Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

    This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep -E \"TMOUT=900\" /etc/bash.bashrc /etc/profile.d/*

    Example result:

    /etc/profile.d/tmout.sh:TMOUT=900

    If the \"TMOUT\" environmental variable is not set, the value is more than \"900\", or is set to \"0\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/profile.d/tmout.sh

    Set its content to the following:

    TMOUT=900
    readonly TMOUT
    export TMOUT
    mesg n 2>/dev/null
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag gid: 'V-PHTN-50-000093'
  tag rid: 'SV-PHTN-50-000093'
  tag stig_id: 'PHTN-50-000093'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  tmoutcontent = inspec.profile.file('tmout.sh')
  describe file('/etc/profile.d/tmout.sh') do
    its('content') { should eq tmoutcontent }
  end
end
