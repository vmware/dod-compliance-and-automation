include_controls 'photon' do
  # VCSA currently cannot implement this control so it must be skipped.
  skip_control 'PHTN-30-000049'
  # Leaving out until tested
  skip_control 'PHTN-30-000240'
end
