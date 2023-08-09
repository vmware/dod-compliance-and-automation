control 'PHTN-30-000057' do
  title 'The Photon operating system must configure auditd to log space limit problems to syslog.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'At the command line, run the following command:

# grep "^space_left " /etc/audit/auditd.conf

Expected result:

space_left = 75

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/audit/auditd.conf

Ensure the "space_left" line is uncommented and set to the following:

space_left = 75

At the command line, run the following commands:

# killproc auditd -TERM
# systemctl start auditd'
  impact 0.5
  tag check_id: 'C-60204r887259_chk'
  tag severity: 'medium'
  tag gid: 'V-256529'
  tag rid: 'SV-256529r887261_rule'
  tag stig_id: 'PHTN-30-000057'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-60147r887260_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left') { should cmp '75' }
  end
end
