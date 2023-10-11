control 'NALB-CO-000034' do
  title 'The NSX Advanced Load Balancer Controller must disable HTTP access.'
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

    Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

    To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system access settings to verify HTTP access is disabled to the controller.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Access.

    If \"HTTP Access\" is enabled, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Under Access, uncheck the box next to \"Enable HTTP Access to System\" and click Save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag gid: 'V-NALB-CO-000034'
  tag rid: 'SV-NALB-CO-000034'
  tag stig_id: 'NALB-CO-000034'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

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
    describe 'HTTP Access Enabled' do
      subject { resultsjson['portal_configuration']['enable_http'] }
      it { should cmp false }
    end
  end
end
