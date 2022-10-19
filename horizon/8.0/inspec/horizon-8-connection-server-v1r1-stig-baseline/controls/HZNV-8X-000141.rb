control 'HZNV-8X-000141' do
  title 'The Horizon Connection Server must not allow unauthenticated access.'
  desc  "
    When the Horizon native smart card capability is not set to \"Required\", the option for \"Unauthenticated Access\" is enabled. This would be true in the case of an external IdP providing authentication via SAML.

    The \"Unauthenticated Access\" option allows users to access published applications from a Horizon Client without requiring AD credentials. This is typically implemented as a convenience when serving up an application that has its own security and user management.

    This configuration is not acceptable in the DoD and must be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab.

    Under \"Horizon Authentication\", find the value in the drop-down below \"Unauthenticated Access\".

    If \"Unauthenticated Access\" is set to \"Enabled\", this is a finding.

    Note: If \"Smart card authentication for users\" is set to \"Required\", this setting is automatically disabled and greyed out, making this control not applicable.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab.

    In the drop-down below  Horizon Authentication >> Unauthenticated Access, select \"Disabled\".

    Click \"OK\".

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000141'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] do
        subject { cs['authentication']['unauthenticatedAccessConfig'] }
        it { should include 'enabled=False' }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
