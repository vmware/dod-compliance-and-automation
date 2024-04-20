control 'VRAA-8X-000008' do
  title 'VMware Aria Automation must configure log shipping to an external system.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

    Off-loading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to off-load log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    On the appliance, at the command line interface, run one of the following commands:

    For Syslog configuration:

    # vracli remote-syslog

    For VMware Aria Operations for Logs configuration:

    # vracli vrli

    Example result for Syslog:

    {
        \"Example_Host\": {
            \"host\": \"10.100.110.120\",
            \"port\": 514,
            \"protocol\": \"tcp\",
            \"ssl_verify\": true,
            \"use_ssl\": false
    }

    Example result for VMware Aria Operations for Logs:

    {
        \"agentId\": \"0\",
        \"environment\": \"prod\",
        \"host\": \"my-vrli.local\",
        \"port\": 443,
        \"scheme\": \"https\",
        \"sslVerify\": false
    }

    If the output does not indicate a valid server similar to the above examples, this is a finding.
  "
  desc 'fix', "
    At the command line interface, run one of the following commands:

    For Syslog configuration:

    # vracli remote-syslog set -id <unique ID to send to syslog> --ca-file </path/to/syslog crt> tcp://<syslog server IP>:<port>

    To use TCP rather than TLS, remove the \"ca-file\" switch and add \"--disable-ssl\" before the host portion.

    For VMware Aria Operations for Logs configuration:

    # vracli vrli set https://<FQDN or IP>:<port>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag satisfies: ['SRG-APP-000125-AS-000084', 'SRG-APP-000181-AS-000255', 'SRG-APP-000356-AS-000202', 'SRG-APP-000515-AS-000203']
  tag gid: 'V-VRAA-8X-000008'
  tag rid: 'SV-VRAA-8X-000008'
  tag stig_id: 'VRAA-8X-000008'
  tag cci: ['CCI-001348', 'CCI-001844', 'CCI-001851', 'CCI-001876']
  tag nist: ['AU-3 (2)', 'AU-4 (1)', 'AU-7 a', 'AU-9 (2)']

  syslogconfig = command('vracli remote-syslog')
  vrliconfig = command('vracli vrli')

  logconfigfound = false

  if syslogconfig.stdout.length.positive?
    logconfigfound = true

    jsoncontent = json({ content: syslogconfig.stdout })

    jsoncontent.each_value do |value|
      describe value do
        its(['host']) { should cmp input('syslogHost') }
        its(['port']) { should cmp input('syslogPort') }
        its(['protocol']) { should cmp input('syslogProtocol') }
        its(['ssl_verify']) { should cmp input('syslogSslVerify') }
        its(['use_ssl']) { should cmp input('syslogUseSsl') }
      end
    end
  end

  if vrliconfig.stdout.length.positive?
    logconfigfound = true

    jsoncontent = json({ content: vrliconfig.stdout })
    describe jsoncontent do
      its(['host']) { should cmp input('syslogHost') }
      its(['port']) { should cmp input('syslogPort') }
      its(['scheme']) { should cmp input('syslogProtocol') }
      its(['ssl_verify']) { should cmp input('syslogSslVerify') }
    end
  end

  unless logconfigfound
    describe 'External logging configuration found' do
      subject { logconfigfound }
      it { should cmp true }
    end
  end
end
