control 'CDAP-10-000131' do
  title 'Cloud Director must enable SSL for AMQP connections.'
  desc  'If you want VMware Cloud Director to send AMQP messages triggered by certain events, you must configure an AMQP broker. You can use the AMQP messages to automate the handling of an underlying user request. By default, the VMware Cloud Director AMQP service sends unencrypted messages. If used the AMQP service must be to encrypt these messages by using SSL.'
  desc  'rationale', ''
  desc  'check', "
    If an AMQP broker is not configured, this is Not Applicable.

    From the Cloud Director provider interface, go to Administration >> Settings >> Extensibility.

    View the \"AMQP Broker\" configuration.

    If \"Use SSL\" is not enabled, this is a finding.
  "
  desc  'fix', "
    The AMQP broker certificate must be trusted to establish an SSL connection and can be done by going to Administration >> Certificate Management >> Trusted Certificates.

    Click Test Remote Connection.

    Enter the URL for the AMQP server and select HTTPS as the verification algorithm and click Connect.

    Review the presented certificate information and click Trust if it is correct.

    From the Cloud Director provider interface, go to Administration >> Settings >> Extensibility.

    Under AMQP Broker click Edit.

    Enable the radio button next to \"Use SSL\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000131'
  tag rid: 'SV-CDAP-10-000131'
  tag stig_id: 'CDAP-10-000131'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('vcdURL')}/api/admin/extension/settings/amqp",
                method: 'GET',
                headers: {
                  'accept' => "#{input('legacyApiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    amqpresults = JSON.parse(result.body)
    if amqpresults['amqpHost'].empty?
      describe 'AMQP not configured...skipping...' do
        skip 'AMQP not configured...skipping...'
      end
    else
      describe amqpresults['amqpUseSSL'] do
        it { should cmp 'true' }
      end
    end
  end
end
