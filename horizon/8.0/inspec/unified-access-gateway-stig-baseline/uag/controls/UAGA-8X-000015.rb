control 'UAGA-8X-000015' do
  title 'The UAG must ensure inbound and outbound traffic is monitored for compliance with remote access security policies.'
  desc  "
    Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

    Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications. With outbound traffic inspection, traffic must be inspected prior to being forwarded to destinations outside of the enclave, such as external email traffic.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Support Settings >> Log Level Settings. Click the \"Gear\" icon to edit.

    If the log level settings does not contain an entry for \"All - INFO\", this is a finding.

    Note: DEBUG and TRACE log levels must be applied only during troubleshooting as these levels can reduce performance and increase the verbose log messages. After you complete troubleshooting using the DEBUG or TRACE log levels, the log level must be reset to INFO or the component or sub-component must be removed from the log settings.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Support Settings >> Log Level Settings. Click the \"Gear\" icon to edit.

    Remove any unnecessary log components.

    Remove any components with a \"DEBUG\" or \"TRACE\" level, unless actively troubleshooting an issue.

    Ensure, at a minimum, that an entry for \"All - INFO\" is added.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000015'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']

  result = uaghelper.runrestcommand('rest/v1/monitor/getLogLevels')
  prohib = ['debug', 'trace']

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent do
      its(['ALL']) { should_not cmp nil }
      its(['ALL']) { should cmp 'info' }
    end

    jsoncontent.each do |key, value|
      describe "Checking #{key}:#{value}" do
        subject { value }
        it { should_not be_in prohib }
      end
    end
  end
end
