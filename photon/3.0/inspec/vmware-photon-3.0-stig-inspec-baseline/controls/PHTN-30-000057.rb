control 'PHTN-30-000057' do
  title 'The Photon operating system must configure auditd to log space limit problems to syslog.'
  desc  'If security personnel are not notified immediately when storage volume reaches 75% utilization, they are unable to plan for audit record storage capacity expansion.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^space_left \" /etc/audit/auditd.conf

    Expected result:

    space_left = 75

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Ensure that the \"space_left\" line is uncommented and set to the following:

    space_left = 75

    At the command line, execute the following command(s):

    # killproc auditd -TERM
    # systemctl start auditd
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-PHTN-30-000057'
  tag rid: 'SV-PHTN-30-000057'
  tag stig_id: 'PHTN-30-000057'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left') { should cmp '75' }
  end
end
