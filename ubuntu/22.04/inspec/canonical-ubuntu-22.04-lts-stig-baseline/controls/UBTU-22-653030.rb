control 'UBTU-22-653030' do
  title 'Ubuntu 22.04 LTS must shut down by default upon audit failure.'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows:

1. If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2. If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify Ubuntu 22.04 LTS takes the appropriate action when the audit storage volume is full by using the following command:

     $ sudo grep -i disk_full_action /etc/audit/auditd.conf
     disk_full_action = HALT

If "disk_full_action" is not set to "HALT", "SYSLOG", or "SINGLE", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to shut down by default upon audit failure.

Add or modify the following line in the "/etc/audit/auditd.conf " file:

disk_full_action = HALT

Restart the "auditd" service for the changes to take effect:

     $ sudo systemctl restart auditd.service

Note: If system availability has been determined to be more important, and this decision is documented with the ISSO, configure Ubuntu 22.04 LTS to notify system administration staff and ISSO staff in the event of an audit processing failure by setting the "disk_full_action" to "SYSLOG" or "SINGLE".'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64323r953593_chk'
  tag severity: 'medium'
  tag gid: 'V-260594'
  tag rid: 'SV-260594r1038966_rule'
  tag stig_id: 'UBTU-22-653030'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-64231r953594_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  describe auditd_conf do
    its('disk_full_action') { should_not be_empty }
    its('disk_full_action') { should cmp /(?:SYSLOG|SINGLE|HALT)/i }
  end
end
