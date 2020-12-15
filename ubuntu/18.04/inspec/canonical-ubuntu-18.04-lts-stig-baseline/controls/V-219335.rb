# encoding: UTF-8

control 'V-219335' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc  "Kernel core dumps may contain the full contents of system memory at
the time of the crash. Kernel core dumps may consume a considerable amount of
disk space and may result in denial of service by exhausting the available
space on the target file system partition."
  desc  'rationale', ''
  desc  'check', "
    Verify that kernel core dumps are disabled unless needed.

    Check if \"kdump\" service is active with the following command:

    # systemctl is-active kdump.service
    inactive

    If the \"kdump\" service is active, ask the System Administrator if the use
of the service is required and documented with the Information System Security
Officer (ISSO).

    If the service is active and is not documented, this is a finding.
  "
  desc  'fix', "
    If kernel core dumps are not required, disable the \"kdump\" service with
the following command:

    # systemctl disable kdump.service

    If kernel core dumps are required, document the need with the Information
System Security Officer (ISSO).
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag gid: 'V-219335'
  tag rid: 'SV-219335r508662_rule'
  tag stig_id: 'UBTU-18-010505'
  tag fix_id: 'F-21059r305334_fix'
  tag cci: ['V-100893', 'SV-109997', 'CCI-001190']
  tag nist: ['SC-24']

  is_kdump_required = input('is_kdump_required')
  if is_kdump_required
    describe service('kdump') do
      it { should be_enabled }
      it { should be_installed }
      it { should be_running }
    end
  else
    describe service('kdump') do
      it { should_not be_enabled }
      it { should_not be_installed }
      it { should_not be_running }
    end
  end
end

