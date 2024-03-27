control 'CFAP-4X-000128' do
  title 'SDDC Manager must schedule automatic password rotation.'
  desc  'As a security measure, you can rotate passwords for the logical and physical accounts on all racks in your system. The process of password rotation generates randomized passwords for the selected accounts. You can rotate passwords manually or set up auto-rotation for accounts managed by SDDC Manager. By default, auto-rotation is enabled for vCenter Server.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI navigate to Administration >> Security >> Password Management.

    Review the rotation schedules for vCenter, PSC, NSX-T, and Backup.

    If a rotation schedule is disabled for these groups of passwords, this is a finding.

    Note: Automatic password rotation is not currently supported for ESXi.
  "
  desc 'fix', "
    From the SDDC Manager UI navigate to Administration >> Security >> Password Management.

    Select a filter on the top right such as vCenter.

    Select the username(s) and click \"Schedule Rotation\" and select a schedule of 30, 60, or 90 days.

    The default password policy for rotated passwords are:
    -20 characters in length
    -At least one uppercase letter, a number, and one of the following special characters: ! @ # $ ^ *
    -No more than two of the same characters consecutively

    Note: If you changed the vCenter Server password length using the vSphere Client or the ESXi password length using the VMware Host Client, rotating the password for those components from SDDC Manager generates a password that complies with the password length that you specified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcManager')}/v1/credentials",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}"
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
