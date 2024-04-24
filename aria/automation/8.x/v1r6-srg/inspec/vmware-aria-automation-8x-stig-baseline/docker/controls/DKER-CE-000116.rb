control 'DKER-CE-000116' do
  title 'Docker CE must disable non-essential, unnecessary, and unsecure DoD ports, protocols, and services.'
  desc  'The Docker Engine is configured by default to listen for API requests via a UNIX domain socket (or IPC socket) created at /var/run/docker.sock on supported Linux distributions. The Docker engine can also be configured to listen for API requests via additional socket types, including both TCP and FD (only on supported systemd-based Linux distributions). If configured to listen for API requests via the TCP socket type the instance is vulnerable to network based attacks and must not be used if unnecessary.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # netstat -anp | grep dockerd | grep \"^tcp\"

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    The Docker daemon can be configured to listen on other ports in several places which all must be checked to find the offending configuration.

    Navigate to and open:

    /usr/lib/systemd/system/docker.service

    In the \"ExecStart\" entry, remove any statement starting with \"-H tcp://\".

    Navigate to and open:

    /etc/docker/daemon.json

    Find the \"hosts\" statement if it exists and remove any statement starting with \"tcp://\"

    Restart the docker daemon by running the following command:

    # systemctl restart docker.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-CTR-000910'
  tag gid: 'V-DKER-CE-000116'
  tag rid: 'SV-DKER-CE-000116'
  tag stig_id: 'DKER-CE-000116'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  fl = file('/usr/bin/netstat')
  if fl.exist?
    describe command('netstat -anp | grep dockerd | grep "^tcp"') do
      its('stdout') { should eq '' }
    end
  else
    describe 'Netstat command not found' do
      skip 'Unable to check, manual verification required'
    end
  end
end
