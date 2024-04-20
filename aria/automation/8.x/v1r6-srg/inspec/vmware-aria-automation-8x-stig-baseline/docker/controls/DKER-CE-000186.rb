control 'DKER-CE-000186' do
  title 'Docker CE must enable live restore.'
  desc  'Enabling live restore ensures availability of containers in the event the docker daemon is down.  Ensuring live restore is on can prevent denial of service attacks on the docker daemon from impacting the application.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # docker info --format '{{ .LiveRestoreEnabled }}'

    Expected output:

    true

    If the output does not return true, this is a finding.
  "
  desc 'fix', "
    To configure live-restore in the daemon.json configuration file, do the following:

    Navigate to and open:

    /etc/docker/daemon.json

    Add or update the following option as seen in the example below.

      \"live-restore\": true

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-DKER-CE-000186'
  tag rid: 'SV-DKER-CE-000186'
  tag stig_id: 'DKER-CE-000186'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe docker.info.LiveRestoreEnabled do
    it 'LiveRestore must be enabled' do
      expect(subject).to cmp true
    end
  end
end
