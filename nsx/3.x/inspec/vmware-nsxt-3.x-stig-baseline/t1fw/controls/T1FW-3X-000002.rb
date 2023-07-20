control 'T1FW-3X-000002' do
  title 'The NSX-T Tier-1 Gateway Firewall must not have any unpublished firewall policies or rules.'
  desc  "
    Unpublished firewall rules may be enabled inadvertently and cause unintended filtering or introduce unvetted/unauthorized traffic flows.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

    For each Tier-1 Gateway, ensure there are no Unpublished changes.

    If there is a message for Total Unpublished Changes and Publish is not greyed out, this is a finding.
  "
  desc 'fix', "
    From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

    For each Tier-1 Gateway with Unpublished changes, review any unpublished changes and click either \"Revert\" or \"Publish\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000019-FW-000004'
  tag gid: 'V-251760'
  tag rid: 'SV-251760r810175_rule'
  tag stig_id: 'T1FW-3X-000002'
  tag fix_id: 'F-55151r810174_fix'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

  describe 'This check is a manual check' do
    skip 'For each Tier-1 Gateway ensure there are no Unpublished changes'
  end
end
