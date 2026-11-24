control 'UBTU-24-100450' do
  title 'Ubuntu 24.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system or storage media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify the audit event multiplexor is configured to offload audit records to a different system or storage media from the system being audited.

Check that audisp-remote plugin is installed:

$ dpkg -l | grep audispd-plugins
ii  audispd-plugins     1:3.1.2-2.1build1.1     amd64     Plugins for the audit event dispatcher

If the packet is "not installed", this is a finding.

Check that the records are being offloaded to a remote server with the following command:

$ sudo grep -i active /etc/audit/plugins.d/au-remote.conf
active = yes

If "active" is not set to "yes", or the line is commented out, or is missing, this is a finding.

Check that audisp-remote plugin is configured to send audit logs to a different system:

$ sudo grep -i ^remote_server /etc/audit/audisp-remote.conf
remote_server = 192.168.122.126

If the "remote_server" parameter is not set, is set with a local address, or is set with an invalid address, this is a finding.'
  desc 'fix', %q(Configure the audit event multiplexor to offload audit records to a different system or storage media from the system being audited.

Install the audisp-remote plugin:

$ sudo apt install -y audispd-plugins

Set the audisp-remote plugin as active by editing the "/etc/audit/plugins.d/au-remote.conf" file:

$ sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audit/plugins.d/au-remote.conf

Set the address of the remote machine by editing the "/etc/audit/audisp-remote.conf" file:

$ sudo sed -i -E 's/(remote_server\s*=).*/\1 <remote addr>/' /etc/audit/audisp-remote.conf

where <remote addr> must be substituted by the address of the remote server receiving the audit log.

Make the audit service reload its configuration files:

$ sudo systemctl restart auditd.service)
  impact 0.3
  tag check_id: 'C-74691r1067149_chk'
  tag severity: 'low'
  tag gid: 'V-270658'
  tag rid: 'SV-270658r1067151_rule'
  tag stig_id: 'UBTU-24-100450'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-74592r1067150_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  audisp_remote_config_file = input('audisp_remote_config_file')

  audit_sp_remote_server = input('audit_sp_remote_server')

  describe package('audispd-plugins') do
    it { should be_installed }
  end

  if file(audisp_remote_config_file).exist?
    describe parse_config_file(audisp_remote_config_file) do
      its('active') { should cmp 'yes' }
      its('remote_server') { should cmp audit_sp_remote_server }
    end
  else
    describe file(audisp_remote_config_file) do
      it { should exist }
    end
  end
end
