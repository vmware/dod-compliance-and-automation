include_controls 'photon' do
  # SELinux not supported yet for SDDC Manager
  skip_control 'PHTN-40-000066'
  # NTP handled by SDDC Manager UI
  skip_control 'PHTN-40-000121'
  # AIDE package not available yet
  skip_control 'PHTN-40-000127'
  skip_control 'PHTN-40-000237'
end
