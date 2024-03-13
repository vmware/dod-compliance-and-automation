include_controls 'photon' do
  # Syslog configuration is done in the UI
  skip_control 'PHTN-30-000039'
  # NTP configuration is done in the UI
  skip_control 'PHTN-50-000058'
end
