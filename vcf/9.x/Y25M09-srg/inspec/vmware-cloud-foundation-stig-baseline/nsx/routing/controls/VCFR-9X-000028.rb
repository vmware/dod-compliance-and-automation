control 'VCFR-9X-000028' do
  title 'The router must not be configured to have any feature enabled that calls home to the vendor.'
  desc  'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> Customer Program.

    Next to Customer Experience Improvement Program, select \"Edit\".

    If \"Join the VMware Customer Experience Improvement Program\" is checked, this is a finding.

    If Schedule is enabled, this is finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> Customer Program.

    Next to Customer Experience Improvement Program, select \"Edit\".

    Uncheck \"Join the VMware Customer Experience Improvement Program\", set \"Schedule\" to disabled, and then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag gid: 'V-VCFR-9X-000028'
  tag rid: 'SV-VCFR-9X-000028'
  tag stig_id: 'VCFR-9X-000028'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/telemetry/config",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('ceip_acceptance') { should cmp false }
      its('schedule_enabled') { should cmp false }
    end
  end
end
