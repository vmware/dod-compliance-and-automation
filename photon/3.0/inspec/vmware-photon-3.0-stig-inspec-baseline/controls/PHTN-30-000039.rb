control 'PHTN-30-000039' do
  title 'The Photon operating system must configure rsyslog to offload system logs to a central server.'
  desc  'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Proper configuration of rsyslog ensures that information critical to forensic analysis of security events is available for future action without any manual offloading or cron jobs.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

     # cat /etc/rsyslog.conf

     The output should be similar to the following where <syslog server:port> is set to the environments approved syslog server:

     *.* @<syslog server:port>;RSYSLOG_syslogProtocol23Format

     If no line is returned or if the line is commented or no valid syslog server is specified, this is a finding.
  "
  desc 'fix', "
    Examples are provided for UDP, TCP, and TLS configurations.  Substitute the environments approved syslog server for <syslog server:port> for the protocol of choice.

    For Example:

    *.* @mysyslog.domain.local:514;RSYSLOG_syslogProtocol23Format

    Navigate to and open:

    /etc/rsyslog.conf

    Remove any existing content and create a new remote server configuration line:

     For UDP

     *.* @<syslog server:port>;RSYSLOG_syslogProtocol23Format

     For TCP

     *.* @@<syslog server:port>;RSYSLOG_syslogProtocol23Format

     For TLS

     *.* @@(o)<syslog server:port>;RSYSLOG_syslogProtocol23Format

    At the command line, execute the following command:

     # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag satisfies: ['SRG-OS-000447-GPOS-00201', 'SRG-OS-000274-GPOS-00104', 'SRG-OS-000275-GPOS-00105', 'SRG-OS-000276-GPOS-00106', 'SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224', 'SRG-OS-000277-GPOS-00107', 'SRG-OS-000304-GPOS-00121']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000039'
  tag cci: ['CCI-001312', 'CCI-002702', 'CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001851', 'CCI-001851', 'CCI-001686', 'CCI-002132']
  tag nist: ['SI-11 a', 'SI-6 d', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-4 (1)', 'AU-4 (1)', 'AC-2 (4)', 'AC-2 (4)']

  describe file('/etc/rsyslog.conf') do
    its('content') { should match /^.*#{input('syslogServer')}.*$/ }
  end
end
