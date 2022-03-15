control 'VCST-67-000019' do
  title "The Security Token Service must limit the number of allowed
connections."
  desc  "Limiting the number of established connections to the Security Token
Service is a basic denial of service protection. Servers where the limit is too
high or unlimited can potentially run out of system resources and negatively
affect system availability."
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/Server/Service/Connector[@port=\"${bio-custom.http.port}\"]/@acceptCount' -

    Expected result:

    acceptCount=\"100\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml.

    Navigate to the <Connector> configured with
port=\"${bio-custom.http.port}\".

    Add or change the following value:

    acceptCount=\"100\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: 'V-239670'
  tag rid: 'SV-239670r816735_rule'
  tag stig_id: 'VCST-67-000019'
  tag fix_id: 'F-42862r816734_fix'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector[@port="${bio-custom.http.port}"]/@acceptCount']) { should cmp "#{input('acceptCount')}" }
  end
end
