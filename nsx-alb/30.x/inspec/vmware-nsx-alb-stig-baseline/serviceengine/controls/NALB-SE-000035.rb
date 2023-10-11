control 'NALB-SE-000035' do
  title 'The NSX Advanced Load Balancer must be configured to remove or disable unrelated or unneeded application proxy services.'
  desc  'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the ALG. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider the separation of gateways that service the DMZ and the trusted network.'
  desc  'rationale', ''
  desc  'check', "
    In NSX ALB, virtual services are the core of the load-balancing and proxy functionality. A virtual service advertises an IP address and ports to the external world and listens for client traffic. When a virtual service receives traffic, it may be configured to:

    1. Proxy the client's network connection.
    2. Perform security, acceleration, load balancing, gathering traffic statistics, and other tasks.
    3. Forward the client's requested data to the destination pool for load balancing.

    From NSX ALB UI, go to Applications >> Virtual Services.

    Review the configured virtual services and determine if they are still actively in use or can be disabled/removed.

    If any virtual services exist that are not actively in use and are enabled, this is a finding.
  "
  desc 'fix', "
    To disable an unwanted virtual service, from NSX ALB UI, navigate to Applications >> Virtual Services >> select the Virtual Service.

    Click on the pencil icon to edit the configuration.

    Click on the enable tab to disable a virtual service and save. The virtual service will be disabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag gid: 'V-NALB-SE-000035'
  tag rid: 'SV-NALB-SE-000035'
  tag stig_id: 'NALB-SE-000035'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  virtualservices = http("https://#{input('avicontroller')}/api/virtualservice",
                      method: 'GET',
                      headers: {
                        'Accept-Encoding' => 'application/json',
                        'X-Avi-Version' => "#{input('aviversion')}",
                        'Cookie' => "sessionid=#{input('sessionCookieId')}",
                      },
                      ssl_verify: false)

  describe virtualservices do
    its('status') { should cmp 200 }
  end

  unless virtualservices.status != 200
    vsjson = JSON.parse(virtualservices.body)
    if vsjson['results'] == []
      impact 0.0
      describe 'No Virtual Services found!' do
        skip 'No Virtual Services found!...skipping.'
      end
    else
      vsjson['results'].each do |vs|
        vsname = vs['name']
        describe "Virtual Server: #{vsname}" do
          subject { vsname }
          it { should be_in "#{input('allowed_virtual_services')}" }
        end
      end
    end
  end
end
