control 'UAGA-8X-000165' do
  title 'The UAG must configure SNMP properly.'
  desc  "
    SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy. Previous versions of the protocol contain well-known security weaknesses that can be easily exploited. As such, SNMPv1 and SNMPv2 receivers must be disabled.

    If SNMP is not being used, it must remain disabled. If SNMP is enabled but properly configured, monitoring information can be sent to a malicious host that can then use this information to plan an attack.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.  Click the \"Gear\" icon.

    If the \"Enable SNMP\" toggle is set to \"Off\", this is not a finding.

    If the \"Enable SNMP\" toggle is set to \"On\", and the \"SNMP Version\" dropdown is set to \"SNMPv3\", this is not a finding.

    If the \"Enable SNMP\" toggle is set to \"On\", and the \"SNMP Version\" dropdown is set to \"SNMPv1+SNMPv2c\", this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.  Click the \"Gear\" icon.

    Either set the \"Enable SNMP\" toggle to \"Off\", or set it to \"On\", and ensure the \"SNMP Version\" is set to \"SNMPv3\", then fill in all required fields.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000165'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    if jsoncontent['snmpEnabled'] == true
      describe jsoncontent['snmpSettings']['version'] do
        it { should cmp 'V3' }
      end
    else
      describe jsoncontent['snmpEnabled'] do
        it { should cmp false }
      end
    end
  end
end
