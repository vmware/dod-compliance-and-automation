include_controls 'photon' do
  # NTP is handled in the application srg for VCD
  skip_control 'PHTN-30-000058'
  # Kernel FIPS mode hasn't been tested yet for VCD
  skip_control 'PHTN-30-000240'
end
