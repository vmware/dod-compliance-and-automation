control 'UBTU-22-653040' do
  title 'Ubuntu 22.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) when the audit record storage volume reaches 25 percent remaining of the allocated capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 25 percent remaining of the allocated capacity, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to notify the SA and ISSO when the audit record storage volume reaches 25 percent remaining of the allocated capacity by using the following command:

     $ sudo grep -i space_left /etc/audit/auditd.conf
     space_left = 25%
     space_left_action = email

If "space_left" is set to a value less than "25%", is commented out, or is missing, this is a finding.

If "space_left_action" is not set to "email", is commented out, or is missing, this is a finding.

Note: If the "space_left_action" is set to "exec", the system executes a designated script. If this script informs the SA of the event, this is not a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to notify the SA and ISSO when the audit record storage volume reaches 25 percent remaining of the allocated capacity.

Add or modify the following lines in the "/etc/audit/auditd.conf " file:

space_left = 25%
space_left_action = email

Restart the "auditd" service for the changes to take effect:

     $ sudo systemctl restart auditd.service

Note: If the "space_left_action" parameter is set to "exec", ensure the command being executed notifies the SA and ISSO.'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64325r953599_chk'
  tag severity: 'low'
  tag gid: 'V-260596'
  tag rid: 'SV-260596r971542_rule'
  tag stig_id: 'UBTU-22-653040'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-64233r953600_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  describe auditd_conf do
    its('space_left') { should cmp >= '25%' }
    its('space_left') { should match /\d{2}%/ }
    its('space_left_action') { should cmp 'email' }
  end
end
