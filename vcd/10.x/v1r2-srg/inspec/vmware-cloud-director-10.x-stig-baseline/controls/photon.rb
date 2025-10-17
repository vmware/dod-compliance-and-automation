include_controls 'photon' do
  # SELinux not supported yet
  skip_control 'PHTN-40-000066'
  # NTP handled by UI (CDAP-10-000084)
  skip_control 'PHTN-40-000121'
  # FIPS is enabled in UI and kernel FIPS should not be enabled independently
  skip_control 'PHTN-40-000182'
end
