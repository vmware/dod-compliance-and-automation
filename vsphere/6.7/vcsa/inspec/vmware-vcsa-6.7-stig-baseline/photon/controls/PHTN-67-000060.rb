control 'PHTN-67-000060' do
  title "The Photon operating system must configure auditd to log space limit
problems to syslog."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75% utilization, they are unable to plan for audit record storage
capacity expansion."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^space_left \" /etc/audit/auditd.conf

    Expected result:

    space_left = 75

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/audit/auditd.conf with a text editor.

    Ensure that the \"space_left\" line is uncommented and set to the following:

    space_left = 75

    At the command line, execute the following command:

    # service auditd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-239131'
  tag rid: 'SV-239131r675201_rule'
  tag stig_id: 'PHTN-67-000060'
  tag fix_id: 'F-42301r675200_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left') { should cmp '75' }
  end
end
