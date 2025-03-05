include_controls 'photon' do
  # SELinux not supported yet for SDDC Manager
  skip_control 'PHTN-40-000066'
  # NTP handled by SDDC Manager UI
  skip_control 'PHTN-40-000121'
  # FIPS is enabled at deployment time and kernel FIPS should not be enabled independently
  skip_control 'PHTN-40-000182'
end
