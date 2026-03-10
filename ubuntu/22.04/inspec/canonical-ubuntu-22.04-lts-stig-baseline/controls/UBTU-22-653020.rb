control 'UBTU-22-653020' do
  title 'Ubuntu 22.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

The auditd service does not include the ability to send audit records to a centralized server for management directly. However, it can use a plug-in for audit event multiplexor to pass audit records to a remote server.

'
  desc 'check', 'Verify the audit event multiplexor is configured to offload audit records to a different system from the system being audited.

Check if the "audispd-plugins" package is installed:

     $ dpkg -l | grep audispd-plugins
     ii     audispd-plugins     1:3.0.7-1build1     amd64     Plugins for the audit event dispatcher

If the "audispd-plugins" package is not installed, this is a finding.

Check that the records are being offloaded to a remote server by using the following command:

     $ sudo grep -i active /etc/audit/plugins.d/au-remote.conf
     active = yes

If "active" is not set to "yes", or the line is commented out, or is missing, this is a finding.

Check that audisp-remote plugin is configured to send audit logs to a different system:

     $ sudo grep -i remote_server /etc/audit/audisp-remote.conf
     remote_server = 240.9.19.81

If the "remote_server" parameter is not set, is set with a local IP address, or is set with an invalid IP address, this is a finding.'
  desc 'fix', %q(Configure the audit event multiplexor to offload audit records to a different system from the system being audited.

Install the "audisp-plugins" package by using the following command:

     $ sudo apt-get install audispd-plugins

Set the audisp-remote plugin as active by editing the "/etc/audit/plugins.d/au-remote.conf" file:

     $ sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audit/plugins.d/au-remote.conf

Set the IP address of the remote system by editing the "/etc/audit/audisp-remote.conf" file:

     $ sudo sed -i -E 's/(remote_server\s*=).*/\1 <remote_server_ip_address>/' /etc/audit/audisp-remote.conf

Restart the "auditd.service" for the changes to take effect:

     $ sudo systemctl restart auditd.service)
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64321r953587_chk'
  tag severity: 'low'
  tag gid: 'V-260592'
  tag rid: 'SV-260592r958754_rule'
  tag stig_id: 'UBTU-22-653020'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-64229r953588_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  config_file = '/etc/audisp/plugins.d/au-remote.conf'
  config_file_exists = file(config_file).exist?
  audit_sp_remote_server = input('audit_sp_remote_server')

  describe package('audispd-plugins') do
    it { should be_installed }
  end

  if config_file_exists
    describe parse_config_file(config_file) do
      its('active') { should cmp 'yes' }
      its('remote_server') { should cmp audit_sp_remote_server }
    end
  else
    describe("#{config_file} exists") do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
