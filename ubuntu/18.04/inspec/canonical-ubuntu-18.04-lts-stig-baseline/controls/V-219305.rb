control 'V-219305' do
  title "The Ubuntu operating system must automatically terminate a user session
    after inactivity time-outs have expired."
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

    Conditions or trigger events requiring automatic session termination can
    include, for example, organization-defined periods of user inactivity, targeted
    responses to certain types of incidents, and time-of-day restrictions on
    information system use.

    This capability is typically reserved for specific Ubuntu operating system
    functionality where the system owner, data owner, or organization requires
    additional assurance.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000279-GPOS-00109"
  tag "gid": 'V-219305'
  tag "rid": "SV-219305r379336_rule"
  tag "stig_id": "UBTU-18-010405"
  tag "fix_id": "F-21029r305244_fix"
  tag "cci": [ "CCI-002361" ]
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
  desc 'check', "Verify the operating system automatically terminates a user session
    after inactivity time-outs have expired.

    Check that the \"ClientAliveInterval\" variable is set to a value of \"600\"
    or less by performing the following command:

    # sudo grep -i clientalive /etc/ssh/sshd_config

    ClientAliveInterval 600

    If \"ClientAliveInterval\" does not exist, is not set to a value of \"600\"
    or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding.
  "
  desc 'fix', "Configure the operating system to automatically terminate a user
    session after inactivity time-outs have expired or at shutdown.

    Modify or append the following line in the \"/etc/ssh/sshd_config\" file
    replacing \"[Interval]\" with a value of \"600\" or less:

    ClientAliveInterval 600

    In order for the changes to take effect, the SSH daemon must be restarted.

    # sudo systemctl restart sshd.service
  "
  client_alive_interval = input('client_alive_interval')
  client_alive_count_max = input('client_alive_count_max')

  describe sshd_config do
    its('ClientAliveInterval') { should cmp <= client_alive_interval }
    its('ClientAliveCountMax') { should cmp >= client_alive_count_max }
  end
end
