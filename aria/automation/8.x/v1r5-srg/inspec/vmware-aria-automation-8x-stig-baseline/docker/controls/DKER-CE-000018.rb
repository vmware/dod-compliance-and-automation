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
    -w /usr/bin/docker -k docker
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
  tag satisfies: ['SRG-APP-000091-CTR-000160', 'SRG-APP-000095-CTR-000170', 'SRG-APP-000096-CTR-000175', 'SRG-APP-000097-CTR-000180', 'SRG-APP-000098-CTR-000185', 'SRG-APP-000099-CTR-000190', 'SRG-APP-000100-CTR-000195', 'SRG-APP-000100-CTR-000200', 'SRG-APP-000101-CTR-000205', 'SRG-APP-000343-CTR-000780', 'SRG-APP-000381-CTR-000905', 'SRG-APP-000474-CTR-001180', 'SRG-APP-000492-CTR-001220', 'SRG-APP-000493-CTR-001225', 'SRG-APP-000495-CTR-001235', 'SRG-APP-000496-CTR-001240', 'SRG-APP-000497-CTR-001245', 'SRG-APP-000499-CTR-001255', 'SRG-APP-000500-CTR-001260', 'SRG-APP-000501-CTR-001265', 'SRG-APP-000503-CTR-001275', 'SRG-APP-000504-CTR-001280', 'SRG-APP-000505-CTR-001285', 'SRG-APP-000507-CTR-001295', 'SRG-APP-000508-CTR-001300', 'SRG-APP-000510-CTR-001310']
  tag gid: 'V-DKER-CE-000018'
  tag rid: 'SV-DKER-CE-000018'
  tag stig_id: 'DKER-CE-000018'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001487', 'CCI-001814', 'CCI-002234', 'CCI-002702']
  tag nist: ['AC-6 (9)', 'AU-12 a', 'AU-12 c', 'AU-3', 'AU-3 (1)', 'CM-5 (1)', 'SI-6 d']
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
