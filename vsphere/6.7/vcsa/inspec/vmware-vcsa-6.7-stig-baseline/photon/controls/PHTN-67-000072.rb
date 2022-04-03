control 'PHTN-67-000072' do
  title "The Photon operating system must generate audit records when
successful/unsuccessful logon attempts occur."
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

    # auditctl -l | grep -E \"faillog|lastlog|tallylog\"

    Expected result:

    -w /var/log/faillog -p wa
    -w /var/log/lastlog -p wa
    -w /var/log/tallylog -p wa

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for
accurate results. Enabling the auditd service is done as part of a separate
control.
  "
  desc 'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -w /var/log/faillog -p wa
    -w /var/log/lastlog -p wa
    -w /var/log/tallylog -p wa

    At the command line, execute the following command:

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag satisfies: ['SRG-OS-000470-GPOS-00214', 'SRG-OS-000472-GPOS-00217',
'SRG-OS-000473-GPOS-00218']
  tag gid: 'V-239143'
  tag rid: 'SV-239143r816646_rule'
  tag stig_id: 'PHTN-67-000072'
  tag fix_id: 'F-42313r816645_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include %r{-w /var/log/faillog -p wa} }
    its('lines') { should include %r{-w /var/log/lastlog -p wa} }
    its('lines') { should include %r{-w /var/log/tallylog -p wa} }
  end
end
