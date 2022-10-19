control 'HZNV-8X-000135' do
  title 'The Horizon Connection Server must disable client initiated TLS renegotiation.'
  desc  "
    The SSL/TLS renegotiation vulnerability is a potential cyber threat in cases when a client can initiate a renegotiation process. An attacker can abuse this situation by making the server unavailable with a Denial of Service attack or can execute a Man-in-the-Middle injection attack into the HTTPS sessions. To avoid potential TLS Renegotiation Denial-of-Service attacks the Client Initiated TLS renegotiation setting must be disabled.

    Note: The Horizon Connection Server disables this option by default.
  "
  desc  'rationale', ''
  desc  'check', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\\Plugins\\wsnm\\TunnelService\\Params\".

    Locate the \"JvmOptions\" key.

    If \"JvmOptions\" does not exist, or the path does not exist, this is not a finding.

    If \"JvmOptions\" exists and does not include the \"-Djdk.tls.rejectClientInitiatedRenegotiation=true\" option, this is a finding.
  "
  desc 'fix', "
    On the Horizon Connection Server, launch the Registry Editor.

    Traverse the registry tree to \"HKLM\\Software\\VMware, Inc.\\VMware VDM\\plugins\\wsnm\\TunnelService\\Params\".

    Locate the \"JvmOptions\" key.

    If \"JvmOptions\" exists:

    Right-click \"JvmOptions\", select \"Modify...\", and ensure the following option exists:

    -Djdk.tls.rejectClientInitiatedRenegotiation=true

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000135'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\VMware, Inc.\\VMware VDM\\Plugins\\wsnm\\TunnelService\\Params') do
    its('JvmOptions') { should_not cmp '-Djdk.tls.rejectClientInitiatedRenegotiation=false' }
  end
end
