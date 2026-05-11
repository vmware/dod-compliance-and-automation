control 'VCFA-9X-000141' do
  title 'VMware Cloud Foundation must be configured to forward vSphere logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Infrastructure Operations >> Configurations >> Log Collection.

    Expand the \"vCenter\" section. For each vCenter instance listed select it and click Edit from the menu on the left to view the current log collection configuration.

    If collection for vCenter Server events, tasks, and alarms is not activated, this is a finding.

    If log collection is not activated for both vCenter Server and ESX, this is a finding.

    If log forwarding is configured to an alternative central log server other than Operations for Logs directly in vCenter and ESX, this is not a finding.
  "
  desc 'fix', "
    In VCF, log collection and analysis is provided by VCF Operations for Logs. Log collection for vCenter and ESX can be configured centrally from VCF Operations.

    Before log collection can be properly configured, the VCF instances integrated with Operations must be successfully enabled for collection.

    From VCF Operations, go to Administration >> Integrations >> Accounts.

    Expand the \"VMware Cloud Foundation\" section and all VCF instances and workload domains and verify the status for each is green and \"Collecting\".

    If collection is not running, select the VCF instance and click \"Start Collecting All\" from the menu on the left.

    Next enable log collection for vSphere on each workload domain. For each workload domain, select Edit from the menu on the left.

    On the vCenter tab, enable \"Activate Log Collection\" and select \"Collect logs directly into Logs cluster\" then click Save.

    Once collection is properly configured on the VCF instance the log collection configuration must be updated to ensure all needed logs are captured.

    From VCF Operations, go to Infrastructure Operations >> Configurations >> Log Collection.

    Expand the \"vCenter\" section. For each workload domain, select Edit from the menu on the left.

    Select \"Override configuration\".

    Activate \"vCenter Server events, tasks and alarms collection\" and enable both the \"Activate for vCenter Logs\" and \"Activate for ESX Logs\" options.

    Select a syslog protocol and optionally activate SSL and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag satisfies: ['SRG-APP-000125', 'SRG-APP-000515']
  tag gid: 'V-VCFA-9X-000141'
  tag rid: 'SV-VCFA-9X-000141'
  tag stig_id: 'VCFA-9X-000141'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
