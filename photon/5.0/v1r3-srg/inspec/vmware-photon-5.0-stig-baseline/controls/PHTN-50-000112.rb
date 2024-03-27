control 'PHTN-50-000112' do
  title 'The Photon operating system must immediately notify the SA and ISSO when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.'
  desc  'If security personnel are not notified immediately when storage volume reaches 75% utilization, they are unable to plan for audit record storage capacity expansion.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditd is alerting when low disk space is detected:

    # grep '^space_left' /etc/audit/auditd.conf

    Expected result:

    space_left = 25%
    space_left_action = SYSLOG

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Ensure the \"space_left\" and \"space_left_action\" lines are uncommented and set to the following:

    space_left = 25%
    space_left_action = SYSLOG

    At the command line, run the following command:

    # pkill -SIGHUP auditd
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-PHTN-50-000112'
  tag rid: 'SV-PHTN-50-000112'
  tag stig_id: 'PHTN-50-000112'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left') { should cmp '25%' }
    its('space_left_action') { should cmp 'SYSLOG' }
  end
end
