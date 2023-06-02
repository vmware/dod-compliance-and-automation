control 'CFAP-5X-000127' do
  title 'The SDDC Manager must schedule automatic password rotation.'
  desc  'As a security measure, you can rotate passwords for the logical and physical accounts on all racks in your system. The process of password rotation generates randomized passwords for the selected accounts. You can rotate passwords manually or set up auto-rotation for accounts managed by SDDC Manager. By default, auto-rotation is enabled for vCenter Server.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Administration >> Security >> Password Management.

    Review the rotation schedules for vCenter, PSC, NSX-T, and Backup.

    If the rotation schedule is disabled for these groups of passwords, this is a finding.

    Note: Automatic password rotation is not currently supported for ESXi.
  "
  desc 'fix', "
    From the SDDC Manager UI, navigate to Administration >> Security >> Password Management.

    Select a filter on the top right such as vCenter.

    Select the usernames and click \"Schedule Rotation\".

    Select a schedule of 30, 60, or 90 days and click \"Yes\" to confirm.

    The default password policy for rotated passwords is:
    -20 characters in length
    -At least one uppercase letter, a number, and one of the following special characters: ! @ # $ ^ *
    -No more than two of the same characters consecutively

    Note: If the vCenter Server password length was changed using the vSphere Client or the ESXi password length using the VMware Host Client, rotating the password for those components from SDDC Manager generates a password that complies with the password length that was specified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFAP-5X-000127'
  tag rid: 'SV-CFAP-5X-000127'
  tag stig_id: 'CFAP-5X-000127'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcManager')}/v1/credentials",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'Authorization' => "#{input('bearerToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    credentials = JSON.parse(result.body)
    credentials['elements'].each do |cred|
      next unless cred['resource']['resourceType'] != 'ESXI'
      name = cred['resource']['resourceName']
      describe json(content: cred.to_json) do
        its(['resource', 'resourceName']) { should cmp name }
        its(['autoRotatePolicy', 'frequencyInDays']) { should cmp >= 30 }
        its(['autoRotatePolicy', 'frequencyInDays']) { should cmp <= 90 }
      end
    end
  end
end
