control 'HZNV-8X-000143' do
  title 'The Horizon Connection Server must be configured to restrict USB passthrough access.'
  desc  "
    One of the many benefits of VDI is the separation of the end user from the \"desktop\" they are accessing. This helps mitigate the risks imposed by physical access. In a traditional desktop scenario, and from a security perspective, physical access is equivalent to ownership. USB devices are physical devices that interact at the driver layer with the guest operating system and are inherently problematic. There are numerous risks posed by USB, including the driver stack, data loss prevention, and malicious devices. Client USB devices are not necessary for general purpose VDI desktops and must be disabled broadly and only enabled selectively as necessary.

    Note: USB mouse, keyboard and smart card devices are abstracted by Horizon and are not affected by these Horizon configurations.
  "
  desc  'rationale', ''
  desc  'check', "
    Interview the SA. USB devices can be blocked in a number of ways:

    1. The desktop OS
    2. A third party DLP solution
    3. Horizon Agent configuration and GPOs
    4. Horizon Connection Server global policies
    5. Horizon Connection Server per-pool policies

    If 1, 2, or 3 are implemented in this environment, this control is not applicable. Number three is addressed in the Horizon Agent STIG.

    Option One - Disable USB Access Globally:

    > Log in to the Horizon Connection Server Console.

    > From the left pane, navigate to Settings >> Global Policies.

    > In the right pane, confirm that \"USB Access\" is set to \"Deny\".

    > If \"USB Access\" is not set to \"Deny\", this is a finding.

    Option Two - Confirm per-pool settings:

    > Log in to the Horizon Connection Server Console.

    > From the left pane, navigate to Inventory >> Desktops.

    > In the right pane, click the name of each pool that does not explicitly require access to USB devices.

    > In the next screen, click the \"Policies\" tab.

    > Confirm that \"Applied Policy\" is set to \"Deny\".

    > If \"Applied Policy\" is not set to \"Deny\", this is a finding.

    > Click the \"Policy Overrides\" tab.

    > Highlight each user.

    > If \"USB Access\" is set to \"Allow\" for any user, ensure the exception is required and authorized.

    > If any user has an override configured that is not required or authorized, this is a finding.
  "
  desc 'fix', "
    Option One - Disable USB Access Globally:

    > Log in to the Horizon Connection Server Console.

    > From the left pane, navigate to Settings >> Global Policies.

    > In the right pane, click \"Edit Policies\".

    > In the drop-down next to \"USB Access\", select \"Deny\".

    > Click \"OK\".

    Option Two - Confirm per-pool settings:

    > Log in to the Horizon Connection Server Console.

    > From the left pane, navigate to Inventory >> Desktops.

    > In the right pane, click the name of each pool that does not explicitly require access to USB devices.

    > In the next screen, click the \"Policies\" tab.

    > Click \"Edit Policies\".

    > In the dropdown next to \"USB Access\", select \"Inherit\".

    > Click \"OK\".

    > Click the \"Policy Overrides\" tab.

    > \"Edit\" or \"Remove\" as necessary to ensure that configured users with \"USB Access\" set to \"Allow\" are as limited as possible.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000143'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/Policies/Get')

  polinfo = JSON.parse(result.stdout)

  describe 'Checking USB Access Global Policy setting' do
    subject { polinfo['effectivePolicies']['allowUSBAccess'] }
    it { should cmp 'Deny' }
  end

  # Get the list of Desktop Pools
  dtpoolraw = horizonhelper.postpowershellrestwithsession('view-vlsi/rest/v1/queryservice/query', '{"entityType":"DesktopSummaryView","queryEntityType":"DesktopSummaryView","sortDescending":false,"startingOffset":0}')

  dtpoollist = JSON.parse(dtpoolraw.stdout)

  # Loop through list, get USB policy for each one
  dtpoollist['results'].each do |pool|
    body = %({"id":"#{pool['id']}"})
    poolinforaw = horizonhelper.postpowershellrestwithsession('view-vlsi/rest/v1/Policies/Get', body)

    poolinfo = JSON.parse(poolinforaw.stdout)

    describe "Checking USB Access Effective Setting on Pool '#{pool['desktopSummaryData'][/displayName=(.*?);/, 1]}'" do
      subject { poolinfo['effectivePolicies']['allowUSBAccess'] }
      it { should cmp 'Deny' }
    end
  end
end
