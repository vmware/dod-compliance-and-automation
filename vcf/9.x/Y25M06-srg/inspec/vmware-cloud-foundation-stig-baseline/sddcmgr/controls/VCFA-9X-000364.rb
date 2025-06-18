control 'VCFA-9X-000364' do
  title 'VMware Cloud Foundation SDDC Manager must be configured to forward logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager appliance command line, run the following to verify audit records are off-loaded to a syslog server:

     #  grep RSYSLOG_SyslogProtocol23Format /etc/rsyslog.conf

     The output should be similar to the following where <syslog server:port> is set to the approved syslog server for the environment:

     *.* @<syslog server:port>;RSYSLOG_SyslogProtocol23Format

     If no line is returned or if the line is commented or no valid syslog server is specified, this is a finding.
  "
  desc 'fix', "
    Examples are provided for UDP and TCP protocols.

    For Example:

    *.* @@myloginsightserver.domain.local:514;RSYSLOG_SyslogProtocol23Format

    Navigate to and open:

    /etc/rsyslog.conf

    To configure a remote syslog service using the TCP protocol, add or update the following line substituting in the appropriate syslog server for the environment.

    *.* @@myloginsightserver.domain.local:514;RSYSLOG_SyslogProtocol23Format

    To configure a remote syslog service using the UDP protocol, add or update the following line substituting in the appropriate syslog server for the environment.

    *.* @myloginsightserver.domain.local:514;RSYSLOG_SyslogProtocol23Format

    Restart the rsyslog service by running the following command:

     # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000364'
  tag rid: 'SV-VCFA-9X-000364'
  tag stig_id: 'VCFA-9X-000364'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
