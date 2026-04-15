control 'NALB-CO-000073' do
  title 'The NSX Advanced Load Balancer Controller must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc  "
    NSX ALB supports SNMPv2c and SNMPv3. SNMPv3 enables user authentication with the server and payload encryption for the messages exchanged with the Avi Controller.

    Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating the malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

    A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

    Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.
  "
  desc  'rationale', ''
  desc  'check', "
    If SNMP is not configured, this is Not Applicable.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> SNMP.

    If SNMP_V2 is configured, this is a finding.

    If SNMP_V3 is configured and \"Auth Type\" is not configured or set to \"MD5\", this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the pencil icon to open the System Settings editor.

    To update the SNMP Version to SNMP_V3, navigate to the SNMP Section.

    Click on the radio button adjacent to SNMP V3.

    Provide the mandatory inputs for Username and Engine ID.

    Select an \"Auth Type\" other than \"MD5\" from the drop-down and provide the required passphrases and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag gid: 'V-NALB-CO-000073'
  tag rid: 'SV-NALB-CO-000073'
  tag stig_id: 'NALB-CO-000073'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

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
    if resultsjson.key?('snmp_configuration')
      snmp_config = resultsjson['snmp_configuration']

      describe 'SNMP Configuration' do
        it 'should not use SNMPv2' do
          expect(snmp_config['version']).not_to eq('SNMP_VER2'), "SNMP v2 configuration detected: #{snmp_config['version']}"
        end
      end

      if snmp_config.key?('snmp_v3_config')
        snmp_v3_config = snmp_config['snmp_v3_config']

        describe 'SNMP Configuration' do
          describe 'SNMP v3 Configuration' do
            it 'should use SHA' do
              auth_type = snmp_v3_config.dig('user', 'auth_type')
              expect(auth_type).to match(/SHA/i), "SNMP v3 Auth type is #{auth_type}, but expected an auth type as 'SHA'"
            end
          end
        end
      end
    else
      impact 0.0
      describe 'SNMP is not configured so this control is not applicable.' do
        skip 'SNMP is not configured so this control is not applicable.'
      end
    end
  end
end
