control 'CDAP-10-000125' do
  title 'Cloud Director must disable or remove plugins that are not used.'
  desc  'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example Cloud Director functionality can be extended with plugins that should be disabled if not used.'
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to More >> Customize Portal.

    Review the list of plugins and determine which are not in use.

    If any plugins are not in use and are enabled, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to More >> Customize Portal.

    Select the plugin(s) that are not used then click Disable or Delete.

    Note: For 3rd party (non-VMware) or custom plugins it is recommended to delete them if not in use.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-CDAP-10-000125'
  tag rid: 'SV-CDAP-10-000125'
  tag stig_id: 'CDAP-10-000125'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  approvedPlugins = input('approvedPlugins')
  result = http("https://#{input('vcdURL')}/cloudapi/extensions/ui",
                method: 'GET',
                headers: {
                  'Accept' => "#{input('apiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    plugins = JSON.parse(result.body)
    plugins.each do |plugin|
      next unless !approvedPlugins.include?(plugin['pluginName'])
      describe plugin do
        its(['enabled']) { should cmp 'false' }
      end
    end
  end
end
