control 'DKER-CE-000018' do
  title 'Docker CE must have audit rules configured for all components.'
  desc  'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, including security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To handle the need to log DoD-defined auditable events, the container platform must offer a mechanism to change and manage the events that are audited.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # auditctl -l | grep docker

    Expected result:

    -w /etc/docker -p wa -k docker
    -w /usr/bin/docker -p rwxa -k docker
    -w /usr/bin/dockerd -p rwxa -k docker
    -w /usr/bin/containerd -p rwxa -k docker
    -w /usr/bin/containerd-shim -p rwxa -k docker
    -w /usr/bin/containerd-shim-runc-v1 -p rwxa -k docker
    -w /usr/bin/containerd-shim-runc-v2 -p rwxa -k docker
    -w /var/run/docker.sock -p rwxa -k docker
    -w /run/containerd/containerd.sock -p rwxa -k docker
    -w /etc/default/docker -p wa -k docker
    -w /usr/lib/systemd/system/docker.service -p rwxa -k docker
    -w /usr/lib/systemd/system/docker.socket -p rwxa -k docker
    -w /var/lib/docker -p wa -k docker
    -w /etc/containerd/config.toml -p wa -k docker

    If the output does not match the expected result, this is a finding.

    Note: The auditd service must be running for this command to provide output.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/docker.STIG.rules

    Add or update the following lines in the file:

    -w /etc/docker -p wa -k docker
    -w /usr/bin/docker -p rwxa -k docker
    -w /usr/bin/dockerd -k docker
    -w /usr/bin/containerd -k  docker
    -w /usr/bin/containerd-shim -k docker
    -w /usr/bin/containerd-shim-runc-v1 -k docker
    -w /usr/bin/containerd-shim-runc-v2 -k docker
    -w /var/run/docker.sock -k docker
    -w /run/containerd/containerd.sock -k docker
    -w /etc/default/docker -p wa -k docker
    -w /usr/lib/systemd/system/docker.service -k docker
    -w /usr/lib/systemd/system/docker.socket -k docker
    -w /var/lib/docker -p wa -k docker
    -w /etc/containerd/config.toml -p wa -k docker

    Reload the rules by running the following command:

    # augenrules --load

    Note: Enable and start the auditd service if needed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-CTR-000150'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'DKER-CE-000018'
  tag fix_id: nil
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe systemd_service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
  describe auditd do
    its('lines') { should include %r{-w /etc/docker -p wa -k docker} }
    its('lines') { should include %r{-w /usr/bin/docker -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/bin/dockerd -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/bin/containerd -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/bin/containerd-shim -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/bin/containerd-shim-runc-v1 -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/bin/containerd-shim-runc-v2 -p rwxa -k docker} }
    its('lines') { should include %r{-w /var/run/docker.sock -p rwxa -k docker} }
    its('lines') { should include %r{-w /run/containerd/containerd.sock -p rwxa -k docker} }
    its('lines') { should include %r{-w /etc/default/docker -p wa -k docker} }
    its('lines') { should include %r{-w /usr/lib/systemd/system/docker.service -p rwxa -k docker} }
    its('lines') { should include %r{-w /usr/lib/systemd/system/docker.socket -p rwxa -k docker} }
    its('lines') { should include %r{-w /var/lib/docker -p wa -k docker} }
    its('lines') { should include %r{-w /etc/containerd/config.toml -p wa -k docker} }
  end
end
