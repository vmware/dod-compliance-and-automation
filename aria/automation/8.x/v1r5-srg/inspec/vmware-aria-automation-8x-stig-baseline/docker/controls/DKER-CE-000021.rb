control 'DKER-CE-000021' do
  title 'Docker CE must produce logs with sufficient information.'
  desc  "
    Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined.

    Ascertaining the correct order of the events that occurred is important during forensic analysis.  Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence.  By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

    Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered.  Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

    In addition to logging event information, application servers must also log the corresponding dates and times of these events. Examples of event data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity, and application server-related system process activity.
  "
  desc  'rationale', ''
  desc  'check', "
    The Docker daemon log level option can be specified as an argument on the dockerd service or through the daemon.json file.

    To check arguments on the dockerd service, execute the following command:

    # ps -ef | grep dockerd | grep log-level

    To check options in the daemon.json file, execute the following command:

    # grep log-level /etc/docker/daemon.json

    If \"log-level\" is not specified as an argument or in the daemon.json file, this is not a finding.

    If \"log-level\" is not set to \"info\", this is a finding.

    Note: The default log-level if not specified is info.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/docker/daemon.json

    Remove completely or set to info the \"log-level\" setting as seen in the example below.

      \"log-level\": \"info\"

    If \"log-level\" is specified as an argument on the dockerd service it must be removed if not set to info.

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-CTR-000165'
  tag satisfies: ['SRG-APP-000226-CTR-000575']
  tag gid: 'V-DKER-CE-000021'
  tag rid: 'SV-DKER-CE-000021'
  tag stig_id: 'DKER-CE-000021'
  tag cci: ['CCI-001464', 'CCI-001665']
  tag nist: ['AU-14 (1)', 'SC-24']
  result = command('ps -ef | grep -v grep | grep dockerd | grep log-level')
  daemon_conf = file('/etc/docker/daemon.json')
  j = json('/etc/docker/daemon.json')
  describe 'Checking log-level settings' do
    it '{ If daemon includes a log-level parameter it must be set to info }' do
      expect(result.stdout).to be_in ['', 'info', nil]
    end

    if daemon_conf.exist?
      it '{ If conf file sets a log-level parameter it must be set to info }' do
        expect(j['iptables']).to be_nil
      end
    end
  end
end
