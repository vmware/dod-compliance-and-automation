control 'NALB-CO-000078' do
  title 'The NSX Advanced Load Balancer Controller must enable FIPS mode to protect the confidentiality of remote sessions.'
  desc  'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc  'rationale', ''
  desc  'check', "
    Review the FIPS mode enablement status.

    From the NSX ALB Controller web interface go to Administration >> Controller >> System Update.

    If FIPS is not enabled, this is a finding.
  "
  desc 'fix', "
    In order to enable FIPS an administrator must update the controller.pkg file.

    To download the controller.pkg, navigate to VMware Customer Connect Portal >> VMware NSX Advanced Load Balancer >> click Download Now.

    From the different versions of NSX ALB, click on the version of NSX ALB installed then download the Upgrade(VMware/OpenStack/AWS/KVM/CSP).

    Navigate to Administration >> Controller >> Software.

    Click on Upload From Computer and choose the NSX ALB controller.pkg file downloaded then click on Open to upload the upgrade package to the image catalog.

    From the NSX ALB Controller web interface go to Administration >> Controller >> System Update.

    Click \"Compliance Mode\".

    Check the box next to \"Enable FIPS\" and click \"Yes, Continue\".

    Note: FIPS mode cannot be enabled if any service engines are present and cannot be turned off.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag satisfies: ['SRG-APP-000179-NDM-000265', 'SRG-APP-000224-NDM-000270', 'SRG-APP-000411-NDM-000330']
  tag gid: 'V-NALB-CO-000078'
  tag rid: 'SV-NALB-CO-000078'
  tag stig_id: 'NALB-CO-000078'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-7', 'MA-4 (6)', 'SC-23 (3)']

  results = http("https://#{input('avicontroller')}/api/systemconfiguration",
                  method: 'GET',
                  headers: {
                    'Accept-Encoding' => 'application/json',
                    'X-Avi-Version' => "#{input('aviversion')}",
                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                  },
                  ssl_verify: false)

  describe results do
    its('status') { should cmp 200 }
  end

  unless results.status != 200
    resultsjson = JSON.parse(results.body)
    describe 'FIPS Mode' do
      subject { resultsjson['fips_mode'] }
      it { should cmp true }
    end
  end
end
