control 'PHTN-67-000040' do
  title "The Photon operating system must configure rsyslog to offload system
logs to a central server."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration. Proper configuration of rsyslog ensures that
information critical to forensic analysis of security events is available for
future action without any manual offloading or cron jobs.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # cat /etc/vmware-syslog/syslog.conf

    The output should be similar to the following (*.* or AO approved logging
events):

    *.* @<syslog server>:port;RSYSLOG_syslogProtocol23Format

    If no line is returned or if the line is commented or no valid syslog
server is specified, this is a finding.

    OR

    Navigate to https://<hostname>:5480 to access the Virtual Appliance
Management Interface (VAMI). Authenticate and navigate to \"Syslog
Configuration\".

    If no site-specific syslog server is configured, this is a finding.
  "
  desc 'fix', "
    Open /etc/vmware-syslog/syslog.conf with a text editor.

    Remove any existing content and create a new remote server configuration
line.

    For UDP (*.* or AO approved logging events):

    *.* @<syslog server>:port;RSYSLOG_syslogProtocol23Format

    For TCP (*.* or AO approved logging events):

    *.* @@<syslog server>:port;RSYSLOG_syslogProtocol23Format

    OR

    Navigate to https://<hostname>:5480 to access the VAMI.

    Authenticate and navigate to \"Syslog Configuration\".

    Click \"Edit\" in the top right.

    Configure a remote syslog server and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag satisfies: ['SRG-OS-000205-GPOS-00083', 'SRG-OS-000274-GPOS-00104',
'SRG-OS-000275-GPOS-00105', 'SRG-OS-000276-GPOS-00106',
'SRG-OS-000277-GPOS-00107', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-239112'
  tag rid: 'SV-239112r816625_rule'
  tag stig_id: 'PHTN-67-000040'
  tag fix_id: 'F-42282r816624_fix'
  tag cci: ['CCI-001312', 'CCI-001683', 'CCI-001684', 'CCI-001685',
'CCI-001686', 'CCI-001851']
  tag nist: ['SI-11 a', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', "AU-4
(1)"]

  describe file('/etc/vmware-syslog/syslog.conf') do
    its('content') { should match /^.*#{input('syslogServer')}.*$/ }
  end
end
