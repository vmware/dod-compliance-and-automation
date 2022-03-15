control 'VCSA-70-000057' do
  title 'The vCenter Server must enable TLS 1.2 exclusively.'
  desc  "TLS 1.0 and 1.1 are deprecated protocols with well published
shortcomings and vulnerabilities. TLS 1.2 should be disabled on all interfaces
and TLS 1.1 and 1.0 disabled where supported. Mandating TLS 1.2 may break third
party integrations and add-ons to vSphere. Test these integrations carefully
after implementing TLS 1.2 and roll back where appropriate. On interfaces where
required functionality is broken with TLS 1.2 this finding is N/A until such
time as the third party software supports TLS 1.2.

    Make sure you modify TLS settings in the following order: 1. vCenter, 2.
ESXi
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt on the vCenter Server Appliance, execute the
following command:

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc scan

    If the output indicates versions of TLS other than 1.2 are enabled, this is
a finding.
  "
  desc 'fix', "
    At the command prompt on the vCenter Server Appliance, execute the
following commands:

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc backup

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc
update -p TLS1.2

    vCenter services will be restarted as part of the reconfiguration, the OS
will not be restarted. You can add the --no-restart flag to restart services at
a later time. Changes will not take effect until all services are restarted or
the appliance is rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000057'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
