/*
    Règles de l'Atelier Firmware pour les calculateurs automobiles.
    Fichier généré : tables de CRC précalculées (en petit- et gros-boutiste,
    entrées 1 à 8 ou 16) et constantes de la norme SHE (Secure Hardware Extension).
    Une table de CRC indique la présence d'un contrôle d'intégrité (protection
    E2E des messages CAN, vérification de la mémoire, du téléchargement…).
*/

rule AUTO_CRC8_SAE_J1850_table
{
    meta:
        description = "Table de CRC-8 SAE J1850 (AUTOSAR E2E profils 1/2/11, OBD)"
        family = "crc"
    strings:
        $t = { 1D 3A 27 74 69 4E 53 E8 F5 D2 CF 9C 81 A6 BB CD }
    condition:
        any of them
}

rule AUTO_CRC8_H2F_table
{
    meta:
        description = "Table de CRC-8H2F (AUTOSAR E2E profil 2)"
        family = "crc"
    strings:
        $t = { 2F 5E 71 BC 93 E2 CD 57 78 09 26 EB C4 B5 9A AE }
    condition:
        any of them
}

rule AUTO_CRC16_CCITT_table
{
    meta:
        description = "Table de CRC-16 CCITT 0x1021 (AUTOSAR E2E profils 5/6/11, UDS, XCP)"
        family = "crc"
    strings:
        $le = { 2110 4220 6330 8440 A550 C660 E770 0881 }
        $be = { 1021 2042 3063 4084 50A5 60C6 70E7 8108 }
    condition:
        any of them
}

rule AUTO_CRC16_ARC_table
{
    meta:
        description = "Table de CRC-16 IBM/ARC 0x8005 (Modbus, divers calculateurs)"
        family = "crc"
    strings:
        $le = { C1C0 81C1 4001 01C3 C003 8002 41C2 01C6 }
        $be = { C0C1 C181 0140 C301 03C0 0280 C241 C601 }
    condition:
        any of them
}

rule AUTO_CRC32_IEEE_table
{
    meta:
        description = "Table de CRC-32 IEEE 802.3 (AUTOSAR Crc_CalculateCRC32, zip, Ethernet)"
        family = "crc"
    strings:
        $le = { 96300777 2C610EEE BA510999 19C46D07 8FF46A70 35A563E9 A395649E 3288DB0E }
        $be = { 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 }
    condition:
        any of them
}

rule AUTO_CRC32_P4_table
{
    meta:
        description = "Table de CRC-32P4 0xF4ACFB13 (AUTOSAR E2E profil 4)"
        family = "crc"
    strings:
        $le = { F50F8530 EA1F0A61 1F108F51 D43F14C2 213091F2 3E201EA3 CB2F9B93 F7159615 }
        $be = { 30850FF5 610A1FEA 518F101F C2143FD4 F2913021 A31E203E 939B2FCB 159615F7 }
    condition:
        any of them
}

rule AUTO_CRC32_C_table
{
    meta:
        description = "Table de CRC-32C Castagnoli (iSCSI, ext4, certains bootloaders)"
        family = "crc"
    strings:
        $le = { 03836BF2 F7703BE1 F4F35013 1F979AC7 1C14F135 E8E7A126 EB64CAD4 CF58D98A }
        $be = { F26B8303 E13B70F7 1350F3F4 C79A971F 35F1141C 26A1E7E8 D4CA64EB 8AD958CF }
    condition:
        any of them
}

rule AUTO_CRC64_ECMA_table
{
    meta:
        description = "Table de CRC-64 ECMA-182 (AUTOSAR E2E profil 7)"
        family = "crc"
    strings:
        $le = { 6F5FA703BE4C2EB3 5BA040A8573684F4 34FFE7ABE97AAA47 335E8FFF84C3D07B }
        $be = { B32E4CBE03A75F6F F4843657A840A05B 47AA7AE9ABE7FF34 7BD0C384FF8F5E33 }
    condition:
        any of them
}

rule AUTO_SHE_constants
{
    meta:
        description = "Constantes SHE (mise à jour des clés du module de sécurité du calculateur)"
        family = "she"
    strings:
        $key_update_enc_c = { 01 01 53 48 45 00 80 00 00 00 00 00 00 00 00 B0 }
        $key_update_mac_c = { 01 02 53 48 45 00 80 00 00 00 00 00 00 00 00 B0 }
        $debug_key_c = { 01 03 53 48 45 00 80 00 00 00 00 00 00 00 00 B0 }
    condition:
        any of them
}
