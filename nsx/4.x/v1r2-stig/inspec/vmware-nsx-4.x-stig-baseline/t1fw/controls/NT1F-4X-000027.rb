control 'NT1F-4X-000027' do
  title 'The NSX Tier-1 Gateway firewall must be configured to inspect traffic at the application layer.'
  desc 'Application inspection enables the firewall to control traffic based on different parameters that exist within the packets such as enforcing application-specific message and field length. Inspection provides improved protection against application-based attacks by restricting the types of commands allowed for the applications. Application inspection all enforces conformance against published RFCs.

Some applications embed an IP address in the packet that needs to match the source address that is normally translated when it goes through the firewall. Enabling application inspection for a service that embeds IP addresses, the firewall translates embedded addresses and updates any checksum or other fields that are affected by the translation. Enabling application inspection for a service that uses dynamically assigned ports, the firewall monitors sessions to identify the dynamic port assignments, and permits data exchange on these ports for the duration of the specific session.'
  desc 'check', 'From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway, review rules that do not have a Context Profile assigned.

For example, if a rule exists to allow SSH by service or custom port then it should have the associated SSH Context Profile applied.

If any rules with services defined have an associated suitable Context Profile but do not have one applied, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway and each rule that should have a Context Profile enabled, click the pencil icon in the Context Profile column.

Select an existing Context Profile or create a custom one then click "Apply".

After all changes are made, click "Publish".

Not all App IDs will be suitable for use in all cases and should be evaluated in each environment before use.

A list of App IDs for application layer rules is available here: https://docs.vmware.com/en/NSX-Application-IDs/index.html.'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Tier-1 Gateway Firewall'
  tag check_id: 'C-69417r994867_chk'
  tag severity: 'medium'
  tag gid: 'V-265500'
  tag rid: 'SV-265500r994869_rule'
  tag stig_id: 'NT1F-4X-000027'
  tag gtitle: 'SRG-NET-000364-FW-000040'
  tag fix_id: 'F-69325r994868_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  # if status is not 200 return a failure but if it's 200 do not run the test so this control does not pass and is properly skipped as a manual review.
  if t1s.status != 200
    describe t1s do
      its('status') { should cmp 200 }
    end
  else
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      impact 0.0
      describe 'No T1 Gateways are deployed. This is Not Applicable.' do
        skip 'No T1 Gateways are deployed. This is Not Applicable.'
      end
    else
      describe 'This check is a manual or policy based check and must be reviewed manually.' do
        skip 'This check is a manual or policy based check and must be reviewed manually.'
      end
    end
  end
end
