# encoding: UTF-8

control 'V-219311' do
  title "The Ubuntu operating system must automatically terminate all network
connections associated with SSH traffic at the end of the session or after 10
minutes of inactivity."
  desc  "Automatic session termination addresses the termination of
user-initiated logical sessions in contrast to the termination of network
connections that are associated with communications sessions (i.e., network
disconnect). A logical session (for local, network, and remote access) is
initiated whenever a user (or process acting on behalf of a user) accesses an
organizational information system. Such user sessions can be terminated (and
thus terminate user access) without terminating network sessions.

    Session termination terminates all processes associated with a user's
logical session except those processes that are specifically created by the
user (i.e., session owner) to continue after the session is terminated.

    Terminating an idle session within a short time period reduces the window
of opportunity for unauthorized personnel to take control of a management
session enabled on the console or console port that has been left unattended.
In addition, quickly terminating an idle session will also free up resources
committed by the managed network element.

    Terminating network connections associated with communications sessions
includes, for example, de-allocating associated TCP/IP address/port pairs at
the operating system level, and de-allocating networking assignments at the
application level if multiple application sessions are using a single operating
system-level network connection. This does not mean that the operating system
terminates all sessions or network access; it only ends the inactive session
and releases the resources associated with that session.

    Conditions or trigger events requiring automatic session termination can
include, for example, organization-defined periods of user inactivity, targeted
responses to certain types of incidents, and time-of-day restrictions on
information system use.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that all network connections associated with SSH traffic are
automatically terminated at the end of the session or after 10 minutes of
inactivity.

    Check that the \"ClientAliveInterval\" variable is set to a value of
\"600\" or less by performing the following command:

    # sudo grep -i clientalive /etc/ssh/sshd_config

    ClientAliveInterval 600

    If \"ClientAliveInterval\" does not exist, is not set to a value of \"600\"
or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to automatically terminate all
network connections associated with SSH traffic at the end of a session or
after a 10 minute period of inactivity.

    Modify or append the following line in the \"/etc/ssh/sshd_config\" file
replacing \"[Interval]\" with a value of \"600\" or less:

    ClientAliveInterval 600

    In order for the changes to take effect, the SSH daemon must be restarted.

    # sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000279-GPOS-00109']
  tag gid: 'V-219311'
  tag rid: 'SV-219311r508662_rule'
  tag stig_id: 'UBTU-18-010416'
  tag fix_id: 'F-21035r485700_fix'
  tag cci: ['V-100845', 'SV-109949', 'CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
  client_alive_interval = input('client_alive_interval')
  client_alive_count_max = input('client_alive_count_max')

  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= client_alive_interval }
  end
end

