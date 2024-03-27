control 'PHTN-50-000111' do
  title 'The Photon operating system must off-load audit records onto a different system or media from the system being audited.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    If another package is used to offload logs, such as syslog-ng, and is properly configured, this is not applicable.

    At the command line, run the following command to verify audit records are off-loaded to a syslog server:

     # cat /etc/rsyslog.conf

     The output should be similar to the following where <syslog server:port> is set to the environments approved syslog server:

     *.* @<syslog server:port>;RSYSLOG_SyslogProtocol23Format

     If no line is returned or if the line is commented or no valid syslog server is specified, this is a finding.
  "
  desc 'fix', "
    Examples are provided for UDP, TCP, and TLS configurations.  Substitute the environments approved syslog server for <syslog server:port> for the protocol of choice.

    For Example:

    *.* @mysyslog.domain.local:514;RSYSLOG_SyslogProtocol23Format

    Navigate to and open:

    /etc/rsyslog.conf

    Remove any existing content and create a new remote server configuration line:

     For UDP

     *.* @<syslog server:port>;RSYSLOG_SyslogProtocol23Format

     For TCP

     *.* @@<syslog server:port>;RSYSLOG_SyslogProtocol23Format

     For TLS

     *.* @@(o)<syslog server:port>;RSYSLOG_SyslogProtocol23Format

    At the command line, run the following command:

     # systemctl restart rsyslog.service
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000274-GPOS-00104', 'SRG-OS-000275-GPOS-00105', 'SRG-OS-000276-GPOS-00106', 'SRG-OS-000277-GPOS-00107', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000447-GPOS-00201', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-PHTN-50-000111'
  tag rid: 'SV-PHTN-50-000111'
  tag stig_id: 'PHTN-50-000111'
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-001851', 'CCI-002132', 'CCI-002702']
  tag nist: ['AC-2 (4)', 'AU-4 (1)', 'SI-6 d']

  describe file('/etc/rsyslog.conf') do
    its('content') { should match /^\*\.\*.*#{input('syslogServer')};RSYSLOG_SyslogProtocol23Format$/ }
  end
end
