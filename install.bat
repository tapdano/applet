:: gp --uninstall build\javacard\TapDano.cap
:: gp --load build\javacard\TapDano.cap
:: gp --pkg 54617044616E6F --applet 54617044616E6F01 --create 54617044616E6F01
:: gp --pkg 54617044616E6F --applet 54617044616E6F01 --create A0000006472F0001
:: gp --pkg 54617044616E6F --applet 54617044616E6F01 --create D2760000850101

gp --uninstall build\javacard\TapDano.cap --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80
gp --load build\javacard\TapDano.cap --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80
gp --pkg 54617044616E6F --applet 54617044616E6F01 --create 54617044616E6F01 --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80
gp --pkg 54617044616E6F --applet 54617044616E6F01 --create A0000006472F0001 --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80
gp --pkg 54617044616E6F --applet 54617044616E6F01 --create D2760000850101 --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80
