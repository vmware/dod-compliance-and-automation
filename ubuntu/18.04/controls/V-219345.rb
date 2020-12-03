control 'V-219345' do
  title 'An application firewall must be enabled on the system.'
  desc  "Firewalls protect computers from network attacks by blocking or
limiting access to open network ports. Application firewalls limit which
    applications are allowed to communicate over the network."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00232"
  tag "gid": 'V-219345'
  tag "rid": "SV-219345r388482_rule"
  tag "stig_id": "UBTU-18-010520"
  tag "fix_id": "F-21069r305364_fix"
  tag "cci": [ "CCI-000366" ]
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
  desc 'check', "Verify the Uncomplicated Firewall is enabled on the
    system by running the following command:

    # systemctl status ufw.service | grep -i \"active:\"

    Active: active (exited) since Mon 2016-10-17 12:30:29 CDT; 1s ago

    If the above command returns the status as \"inactive\", this is a finding.

    If the Uncomplicated Firewall is not installed ask the System Administrator
    if another application firewall is installed. If no application firewall is
    installed this is a finding.
  "
  desc 'fix', "Enable the Uncomplicated Firewall by using the following command:

    # sudo systemctl enable ufw.service

    If the Uncomplicated Firewall is not currently running on the system, start
    it with the following command:

    # sudo systemctl start ufw.service
  "
  describe service('ufw') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
