control 'NDFW-4X-000027' do
  title 'The NSX Distributed Firewall must be configured to inspect traffic at the application layer.'
  desc  "
    Application inspection enables the firewall to control traffic based on different parameters that exist within the packets such as enforcing application-specific message and field length. Inspection provides improved protection against application-based attacks by restricting the types of commands allowed for the applications. Application inspection all enforces conformance against published RFCs.

    Some applications embed an IP address in the packet that needs to match the source address that is normally translated when it goes through the firewall. Enabling application inspection for a service that embeds IP addresses, the firewall translates embedded addresses and updates any checksum or other fields that are affected by the translation. Enabling application inspection for a service that uses dynamically assigned ports, the firewall monitors sessions to identify the dynamic port assignments, and permits data exchange on these ports for the duration of the specific session.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Security >> Distributed Firewall >> All Rules.

    Review rules that do not have a Context Profile assigned.

    For example, if a rule exists to allow SSH by service or custom port then it should have the associated SSH Context Profile applied.

    If any rules with services defined have an associated suitable Context Profile but do not have one applied, this is a finding.

    Note: This control does not apply to ethernet rules.

    Not all App IDs will be suitable for use in all cases and should be evaluated in each environment before use.

    A list of App IDs for application layer rules is available here: https://docs.vmware.com/en/NSX-Application-IDs/index.html
  "
  desc 'fix', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

    For each rule that should have a Context Profile enabled, click the pencil icon in the Context Profile column.

    Select an existing Context Profile or create a custom one then click \"Apply.

    After all changes are made, click \"Publish\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000364-FW-000040'
  tag gid: 'V-NDFW-4X-000027'
  tag rid: 'SV-NDFW-4X-000027'
  tag stig_id: 'NDFW-4X-000027'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
