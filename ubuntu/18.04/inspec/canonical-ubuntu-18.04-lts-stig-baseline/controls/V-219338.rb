control 'V-219338' do
  title "The Ubuntu operating system must notify designated personnel if baseline
    configurations are changed in an unauthorized manner. The file integrity tool must
    notify the system administrator when changes to the baseline configuration or anomalies
    in the operation of any security functions are discovered."
  desc  "Unauthorized changes to the baseline configuration could make the
    system vulnerable to various attacks or allow unauthorized access to the Ubuntu
    operating system. Changes to Ubuntu operating system configurations can have
    unintended side effects, some of which may be relevant to security.

    Security function is defined as the hardware, software, and/or firmware of
    the information system responsible for enforcing the system security policy and
    supporting the isolation of code and data on which the protection is based.
    Security functionality includes, but is not limited to, establishing system
    accounts, configuring access authorizations (i.e., permissions, privileges),
    setting events to be audited, and setting intrusion detection parameters.

    Detecting such changes and providing an automated response can help avoid
    unintended, negative consequences that could ultimately affect the security
    state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO
    and SAs must be notified via email and/or monitoring system trap when there is
    an unauthorized modification of a configuration item.

    Notifications provided by information systems include messages to local
    computer consoles, and/or hardware indications, such as lights.

    This capability must take into account operational requirements for
    availability for selecting an appropriate response. The organization may choose
    to shut down or restart the information system upon security function anomaly
    detection.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000363-GPOS-00150"
  tag "satisfies": nil
  tag "gid": 'V-219338'
  tag "rid": "SV-219338r379816_rule"
  tag "stig_id": "UBTU-18-010508"
  tag "fix_id": "F-21062r305343_fix"
  tag "cci": [ "CCI-001744","CCI-002702" ]
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
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) notifies the
    system administrator when anomalies in the operation of any security functions are discovered.

    Check that AIDE notifies the system administrator when anomalies in the operation of any
    security functions are discovered with the following command:

    #sudo grep SILENTREPORTS /etc/default/aide

    SILENTREPORTS=no

    If SILENTREPORTS is uncommented and set to yes, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to notify designated personnel if baseline
    configurations are changed in an unauthorized manner.

    Modify the \"SILENTREPORTS\" parameter in the \"/etc/default/aide\" file with a value
    of \"no\" if it does not already exist.
  "
  describe file('/etc/cron.daily/aide') do
    it { should exist }
  end

  describe parse_config_file('/etc/default/aide').params['SILENTREPORTS'] do
    it { should eq 'yes' }
  end
end
