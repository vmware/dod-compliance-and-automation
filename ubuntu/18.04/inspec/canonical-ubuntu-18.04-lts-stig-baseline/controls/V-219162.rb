control 'V-219162' do
  title "The Ubuntu operating system audit event multiplexor must be configured to off-load
    audit logs onto a different system or storage media from the system being audited."
  desc  "Information stored in one location is vulnerable to accidental or incidental
    deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.
  "

  impact 0.3
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "gid": 'V-219162'
  tag "rid": "SV-219162r466199_rule"
  tag "stig_id": "UBTU-18-010025"
  tag "fix_id": "F-20886r304815_fix"
  tag "cci": [ "CCI-001851" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the audit event multiplexor is configured to off-load audit records to
    a different system or storage media from the system being audited.

    Check that audisp-remote plugin is installed:

    # sudo dpkg -s audispd-plugins

    If status is \"not installed\", verify that another method to off-load audit logs has
    been implemented.

    Check that the records are being off-loaded to a remote server with the following command:

    # sudo grep -i active /etc/audisp/plugins.d/au-remote.conf

    active = yes

    If \"active\" is not set to \"yes\", or the line is commented out, ask the System
    Administrator to indicate how the audit logs are off-loaded to a different system or
    storage media.

    If there is no evidence that the system is configured to off-load audit logs to a
    different system or storage media, this is a finding.
  "

  desc 'fix', "Configure the audit event multiplexor to off-load audit records to a different
    system or storage media from the system being audited.

    Install the audisp-remote plugin:

    # sudo apt-get install audispd-plugins -y

    Set the audisp-remote plugin as active, by editing the /etc/audisp/plugins.d/au-remote.conf file:

    # sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf

    Set the address of the remote machine, by editing the /etc/audisp/audisp-remote.conf file:

    # sudo sed -i -E 's/(remote_server\s*=).*/ remote addr/' audisp-remote.conf

    where remote addr must be substituted by the address of the remote server receiving the
    audit log.

    Make the audit service reload its configuration files:

    # sudo systemctl restart auditd.service
  "

  describe 'Not Applicable' do
    skip 'Logging (auditsp-remote)'
  end
end
