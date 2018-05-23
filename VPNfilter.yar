

rule VPNFilter {
   meta:
      description = "Filter for 2nd stage malware used in VPNfilter attack"
      author = "Christiaan Beek @ McAfee Advanced Threat Research"
      reference = "https://blog.talosintelligence.com/2018/05/VPNFilter.html"
      date = "2018-05-23"
      hash1 = "9eb6c779dbad1b717caa462d8e040852759436ed79cc2172692339bc62432387"
      hash2 = "4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b"
      hash3 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
      hash4 = "0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b"
      hash5 = "8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1"
      hash6 = "776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d"
      hash7 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
      hash8 = "d6097e942dd0fdc1fb28ec1814780e6ecc169ec6d24f9954e71954eedbc4c70e"
   strings:
      $s1 = "id-at-postalAddress" fullword ascii
      $s2 = "/bin/shell" fullword ascii
      $s3 = "Usage does not match the extendedKeyUsage extension" fullword ascii
      $s4 = "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)." fullword ascii
      $s5 = "Remote I/O error" fullword ascii
      $s6 = "The CRL is signed with an unacceptable key (eg bad curve, RSA too short)." fullword ascii
      $s7 = "Usage does not match the keyUsage extension" fullword ascii
      $s8 = "id-at-postalCode" fullword ascii
      $s9 = "sha-1WithRSAEncryption" fullword ascii
      $s10 = "Postal code" fullword ascii
      $s11 = "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU" fullword ascii
      $s12 = "id-ce-extKeyUsage" fullword ascii
      $s13 = "Unique Identifier" fullword ascii
      $s14 = "/etc/config/hosts" fullword ascii
      $s15 = "id-at-uniqueIdentifier" fullword ascii
      $s16 = "id-kp-serverAuth" fullword ascii
      $s17 = "Usage does not match the nsCertType extension" fullword ascii
      $s18 = "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)." fullword ascii
      $s19 = "%s%-18s: %d bits" fullword ascii
      $s20 = "id-ce-keyUsage" fullword ascii
   condition:
      ( uint16(0) == 0x457f and
        filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

