control 'UBTU-22-213015' do
  title 'Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed by using the following command:

$ systemctl status kdump-tools.service
kdump-tools.service
Loaded: masked (Reason: Unit kdump-tools.service is masked.)
Active: inactive (dead)

If "kdump-tools.service" is not masked and inactive, ask the system administrator (SA) if the use of the service is required and documented with the information system security officer (ISSO).

If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable and mask "kdump-tools.service" by using the following command:

$ sudo systemctl mask kdump-tools --now

If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64202r1044780_chk'
  tag severity: 'medium'
  tag gid: 'V-260473'
  tag rid: 'SV-260473r1044782_rule'
  tag stig_id: 'UBTU-22-213015'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag fix_id: 'F-64110r1044781_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  is_kdump_required = input('is_kdump_required')
  if is_kdump_required
    impact 0.0
    describe 'kdump service indicated as required on this system...skipping...' do
      skip 'kdump service indicated as required on this system...skipping..'
    end
  elsif package('kdump-tools').installed?
    describe systemd_service('kdump-tools.service') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe systemd_service('kdump-tools.service').params['LoadState'] do
      it { should cmp 'masked' }
    end
    describe systemd_service('kdump-tools.service').params['UnitFileState'] do
      it { should cmp 'masked' }
    end
  else
    describe systemd_service('kdump-tools.service') do
      it { should_not be_installed }
    end
  end
end
