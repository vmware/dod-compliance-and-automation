control 'VCSA-70-000253' do
  title 'The vCenter server must enforce SNMPv3 security features where SNMP is required.'
  desc  "
    SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy while previous versions of the protocol contained well-known security weaknesses that were easily exploited. SNMPv3 can be configured for identification and cryptographically based authentication.

    SNMPv3 defines a user-based security model (USM) and a view-based access control model (VACM). SNMPv3 USM provides data integrity, data origin authentication, message replay protection, and protection against disclosure of the message payload. SNMPv3 VACM provides access control to determine whether a specific type of access (read or write) to the management information is allowed. Implement both VACM and USM for full protection.

    SNMPv3 must be disabled by default and enabled only if used. SNMP v3 provides security feature enhancements to SNMP, including encryption and message authentication.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt on the vCenter Server Appliance, execute the following command(s):

    # appliancesh
    # snmp.get

    Note: The \"appliancesh\" command is not needed if the default shell has not been changed for root.

    If \"Enable\" is set to \"False\", this is not a finding.

    If \"Enable\" is set to \"True\" and \"Authentication\" is not set to \"SHA1\", this is a finding.

    If \"Enable\" is set to \"True\" and \"Privacy\" is not set to \"AES128\", this is a finding.

    If any \"Users\" are configured with a \"Sec_level\" that does not equal \"priv\", this is a finding.
  "
  desc 'fix', "
    At the command prompt on the vCenter Server Appliance, execute the following command(s):

    # appliancesh
    # snmp.set --authentication SHA1
    # snmp.set --privacy AES128

    To change the security level of a user, run the following command:

    # snmp.set --users <username>/<auth_password> <priv_password>/priv
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000575'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000253'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
