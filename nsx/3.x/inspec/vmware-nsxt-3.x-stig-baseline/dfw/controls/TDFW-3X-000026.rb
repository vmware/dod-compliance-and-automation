control 'TDFW-3X-000026' do
  title 'The NSX-T Distributed Firewall must be configured to send traffic log entries to a central audit server for management and configuration of the traffic log entries.'
  desc 'Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

Ensure at least one syslog server is configured on the firewall.

If the product inherently has the ability to store log records locally, the local log must also be secured. However, this requirement is not met since it calls for a use of a central audit server.'
  desc 'check', 'Verify NSX-T Distributed Firewall is configured to send traffic log entries to a central audit server for management and configuration of the traffic log entries.

Log in to vSphere vCenter https interface with credentials authorized for administration. Navigate to Browse to the host in the vSphere Client inventory >> Configure >> System >> Advanced System Settings >> Edit >> Syslog.global.LogHost.

Verify a STIG compliant events server is configured.

If Syslog.global.LogHost is not configured with a STIG compliant events server, this is a finding.'
  desc 'fix', 'Change configuration of NSX-T Distributed Firewall to send traffic log entries to a central audit server for management and configuration of the traffic log entries.

Log in to vSphere vCenter https interface with credentials authorized for administration, navigate to Browse to the host in the vSphere Client inventory >> Configure >> System >> Advanced System Settings >> Edit >> Syslog.global.LogHost >> value >> ssl://hostName1:1514 >> OK.

Note: Configure the syslog or SNMP server to send an alert if the events server is unable to receive events from the NSX-T and also if denial-of-service (DoS) incidents are detected. This is true if the events server is STIG compliant.'
  impact 0.5
  tag check_id: 'C-55167r810042_chk'
  tag severity: 'medium'
  tag gid: 'V-251730'
  tag rid: 'SV-251730r863248_rule'
  tag stig_id: 'TDFW-3X-000026'
  tag gtitle: 'SRG-NET-000333-FW-000014'
  tag fix_id: 'F-55121r810043_fix'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  describe 'Part of this check is a manual or policy based check' do
    skip 'This check it covered as part of the ESXi STIG.'
  end
end
