control 'NDFW-4X-000001' do
  title 'The NSX Distributed Firewall must verify time-based firewall rules.'
  desc  "
    With time windows, security administrators can restrict traffic from a source or to a destination, for a specific time period.

    Time windows apply to a firewall policy section, and all the rules in it. Each firewall policy section can have one time window. The same time window can be applied to more than one policy section. If you want the same rule applied on different days or different times for different sites, you must create more than one policy section. Time-based rules are available for distributed and gateway firewalls on both ESXi and KVM hosts.

    If time windows are not verified and periodically checked, a malicious actor could create time windows to effectively disable rules while not being obvious to firewall administrators.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

    For each category, verify each Policy has no time windows configured or any existing time windows are expected. This can be viewed by clicking on the clock icon in each Policy section.

    If there are unexpected or misconfigured time windows, this is a finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

    Navigate to the offending Category and Policy section, click on the clock icon, then delete or modify the time window for that Policy. Click \"Apply\".

    After all changes are made click \"Publish\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000019-FW-000003'
  tag gid: 'V-NDFW-4X-000001'
  tag rid: 'SV-NDFW-4X-000001'
  tag stig_id: 'NDFW-4X-000001'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

  result = http("https://#{input('nsxManager')}/policy/api/v1/infra/firewall-schedulers",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('result_count') { should cmp '0' }
    end
  end
end
