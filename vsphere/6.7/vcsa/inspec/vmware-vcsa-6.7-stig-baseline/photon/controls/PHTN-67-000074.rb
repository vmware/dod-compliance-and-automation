control "PHTN-67-000074" do
  title "The Photon operating system auditd service must generate audit records
for all account creations, modifications, disabling, and termination events."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep -E /etc/security/opasswd

    If any of these are not listed with a permissions filter of at least \"w\",
this is a finding.
  "
  desc  'fix', "
    At the command line, execute the following command:

    # echo '-w /etc/security/opasswd -p wa -k opasswd' >>
/etc/audit/rules.d/audit.STIG.rules
    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag gid: 'V-239145'
  tag rid: 'SV-239145r675243_rule'
  tag stig_id: 'PHTN-67-000074'
  tag fix_id: 'F-42315r675242_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its("lines") { should include %r{-w /etc/security/opasswd -p wa -k opasswd} }
  end

end

