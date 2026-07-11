import KeygateCore

/// Throwaway private keys generated with `ssh-keygen` / `openssl` purely as import
/// test fixtures. Each fingerprint is the independent `ssh-keygen -l` value.
struct ImportVector {
    let label: String
    let pem: String
    let passphrase: String?
    let fingerprint: String
    let expectedType: SSHKeyType
}

let importVectors: [ImportVector] = [
    ImportVector(
        label: "openssh ed25519 (plain)",
        pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACDu19jEBiDEK/jFcjvQyqqHPFUQrFS2VXkYZKd5SIY4pgAAAJAzGmA3Mxpg
        NwAAAAtzc2gtZWQyNTUxOQAAACDu19jEBiDEK/jFcjvQyqqHPFUQrFS2VXkYZKd5SIY4pg
        AAAEBRF+Si9aLiJivskeE6ugNAUgzCuoRA7jGh1W+sQXOC4e7X2MQGIMQr+MVyO9DKqoc8
        VRCsVLZVeRhkp3lIhjimAAAAC2ltcC1lZDI1NTE5AQI=
        -----END OPENSSH PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:ooLDPdrmKHdy4kFXqTOGxOXpB4UhcH9C5m/EkkLSx6o",
        expectedType: .ed25519
    ),
    ImportVector(
        label: "openssh ecdsa p256 (plain)",
        pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSIYY/K32fEWPRWivdbJAqFo8Cn/e9L
        XiyIqXAc8IPABweDXFJKyJUuQ44TUc2XE9KzQNnfLdgzDw74RlX/mBvBAAAAqKNb8zejW/
        M3AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIhhj8rfZ8RY9FaK
        91skCoWjwKf970teLIipcBzwg8AHB4NcUkrIlS5DjhNRzZcT0rNA2d8t2DMPDvhGVf+YG8
        EAAAAhALkJyLwkntzY73+8hZdWo0cVpJHz52NqKrCgDK7E+2ZSAAAACWltcC1lY2RzYQEC
        AwQFBg==
        -----END OPENSSH PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:r5KaNaN/2fgmpR2IdN2cbuz8GEQBFNZpCCvQssqiQJI",
        expectedType: .ecdsaP256
    ),
    ImportVector(
        label: "openssh rsa (plain)",
        pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAQEAwRDJRZw8b1nLZ7B/746Q6BhrMypOf5u2AeazJDDtAYqQ/0nk3+m2
        zfUH1XVDm+JeieKb2wKga+ogz/OetiLoQDRcwL7Rli3MFdmX4O+q/H6+TtqLjw1VdTvrrq
        63vYWtw5bqtAJmuBmzN+aov543sCycX/LKU9XxcQj3kWQSy+HeeoHN//lvNpxiOdhoQ6IA
        u7/jobI5L3NzHEfOsq46MfYFhvbGaDYe8tuFUbpRtkgWGKdmarb2TR9zcR60xPK6eHQpI2
        srPf89nmoB/Qf5FRHCUeLge6k5mDQcgKTyMOsR7rvI0dFg+5PrBLSsjMXGw9+zh5Q+AOPr
        wVuvVm6PcQAAA8BcZkcLXGZHCwAAAAdzc2gtcnNhAAABAQDBEMlFnDxvWctnsH/vjpDoGG
        szKk5/m7YB5rMkMO0BipD/SeTf6bbN9QfVdUOb4l6J4pvbAqBr6iDP8562IuhANFzAvtGW
        LcwV2Zfg76r8fr5O2ouPDVV1O+uurre9ha3Dluq0Ama4GbM35qi/njewLJxf8spT1fFxCP
        eRZBLL4d56gc3/+W82nGI52GhDogC7v+Ohsjkvc3McR86yrjox9gWG9sZoNh7y24VRulG2
        SBYYp2ZqtvZNH3NxHrTE8rp4dCkjays9/z2eagH9B/kVEcJR4uB7qTmYNByApPIw6xHuu8
        jR0WD7k+sEtKyMxcbD37OHlD4A4+vBW69Wbo9xAAAAAwEAAQAAAQBWvfkAOor4qIp4Atfo
        RNCcRuRbL6XnNYmX3xQbrZO+vogY+xVG+RW2AWJMqIwAzLsXDmZiBxMWiTHG3LkxMgvRVP
        VbcCBwbhEkvAe9+1CCc1uDyDMtyZrculhQupU5JIeGuhanW/DUxE8+TXcB6M8ya0iy3z3C
        XvxEgffhLeo4CXHQdPhqyyHirLw/uf6i4DVHg/bJXQT/CbueB0BO3WNymxK4+vEw/RaWdD
        J0VCTb/EusM94FpznjOr9jXUE+BDEyA8X7L5OD5AO04hL6znJEIISCK31a0z2fcMBgpQ00
        1i0kaQ36aO3mq0Z6Gj1JucOsmKwtfhJUtPOAuO0WOZQBAAAAgQDbVfoa+AYuxvVuegQQo2
        3VDC8+hIAZ7uCnqd0UoDQW2VKuxBgcpd+850tSVt5OQnsAJoHhz2sQax8ZE1c6wP4aKM4k
        O1fuujDxI96wRflJXcCFvdicZGd07EwEvWXyf+dZL88dD+ZHkSqGJo/zJrVfosjUes58Ab
        sE385PgzTKeQAAAIEA8idzKZuFlcvVFinaH4HSnbgQksCl6Nvp+qUbe3TflwMqu6nRi87E
        NwewIpLJUcUB3nzhznBG0MryZotXbi0OAnu5jnap7Ao+Tyh0LVdrpg0swjAyykxi9cdmCM
        CawhmkgagfzTa7071nQCDy7ztquzWe4YK4ze9JA4WA6jF6UrEAAACBAMwazI8PFp2hAeNI
        8lyArvKMh27hPbYBEzldglM0pWpms6nhwZnRkDwiZ8ss/LEaQd1J/5lohYVSs0QEhi1cSE
        qPft3WcoGfIXva5JLrhE08S9RnET+KRW9gUQWOzQsC4DLTYjlbQtQLBDQdgYeWjVieIms3
        tQ30+QURCDLl97jBAAAAB2ltcC1yc2EBAgM=
        -----END OPENSSH PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:awOETKxWSpBmTZJR3HHBifyrsD65Kqfl5R6gBNXHSoU",
        expectedType: .rsa
    ),
    ImportVector(
        label: "pem pkcs8 rsa (plain)",
        pem: """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6SiKFvnxv9HoR
        NAopVP9PaTCWRN2CMlKpDTk1++kC9tN2cxwbHLp099Q8rsugtQ0h1n03eV7XHhwt
        dLevvWxTfJ16//kbLJ0/y4LciHUK4ZbNZRPU0GLqeemS4bYxVet56XDpteL5DOHE
        fWqEDutC8kI/2mRk/Dw5z6Gk9bs0N6kkOOuyqnTbs9w1r3RIfWM7VpQG5B8o2KMJ
        6yA7OhTTVfQ5use/3qamcZIrahLaCjJiYINAPpke6XhiXuVOiNR2vRH/MMujyNfb
        Ek0mfwW9KXQC26d/xMcoiOBQki11gABIio5BFDYAPbeq2pODL3KeqguZcn+iB1wL
        nPgn3f9jAgMBAAECggEAQzj3Ri3bt4aP+d8+f3W1f5FkwATvrci8/VXRPEK/7Zrl
        6ctV7A6s1gKMKq2ku0Q6DejZXIhGiffKkTiaBCeljGbeaQEvgffScq/cc/olyhxn
        j4yW4GemGhiOCbu7RAhOJbrwTNWepuJYIdBj/G1pxcmn0GTdb3d5wB7FpMIroIaK
        AKer1dZaPSbMpDnqtKZlbHQsO0dAimVxke++wb65Ghtvnj5kNxpmLa6/5SIBpVM4
        NurlyxngvfzZjp/ZpRVzuFB9t+Lo1dVJQteJ9y4GK9U7AefshuYsliOKsROHzLrK
        L7raVNcs18yo2ty19tYqG7qtdhEyRsK9FVcHIkdniQKBgQD9VANX5+pjLnKrfVwt
        py9IW7r3VPuV5mIQ8kOa97PNtuYd+CcgEI1gnXvqIfVyIKbhDMo/5S9YrgH7oHdi
        HSNzHhlLSdLf4kVxM9u0+z5V89xVEKBEZ9KckzKfd+EmxyeBASQUo9xZfsQcAjkG
        +tVsK4NT+ON9E5RyYaOMaD3q3wKBgQC8QR4MoDH6wTy2BMEjrlDMsnNNop5ElvlW
        OePwJ7iEpyc3EUPIiIZgvUWoV1/3ICamD1pvwoG0uXUrbJldL+l1Pr597ZL/ssSy
        Ph2cyI+6FRqwY6KeyM7I+JnCfZYHqc27jr9QpRfjRYrgrFO6491avr6RbbencWqG
        a2/qtiA//QKBgQD3/20ee52L5wa/N4Qr9UVmktagFwQMpXNPn7vrU58kPm9c23iB
        /XJKKSIL/Z6pUanNG5ZLovQM3px2V4tH87qmkcq1V9om7v6IafomXOeTgZ4rcJFV
        JkaancerMdKrAcB8nD9ULW4j9uPJf6uQV7LjqF1ysW8THT3wFAHmDI7BBQKBgASw
        1q/X2gb2g63BZpKeCFNhavAXSjxJSsM0RBK62qUriRWdL4Qyqq6EaNTuAG0m9u+S
        WF2KijLXoCzJ0vR4eie6vYJjxhLrAG20kIZUlQg8+GJGyUmNlWF6mFI5UOC2AXNX
        9jprMrIuDGzWvmtcvCpDsHntMvNQJyhcSvidOyZ9AoGAQEL+/iRgT/LuaJf/ZU7V
        UwnTO6EoLYEGs3FpAHyb/aNfEbgyRyz/v/uvUWHFwrnLlZW485R9o9WDXqnLPa5K
        6vZj0/bvUjJu75be9gdnQPet8RecpDk6FHytlmvxQ7YED7awHy13f4GIzJCVas/d
        IbUfu60zXfcYFgKCf053C40=
        -----END PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:1zzb8TW9g4TXSBHM2/S4wCGZCFUYuwJ/Tg4sBwJeL94",
        expectedType: .rsa
    ),
    ImportVector(
        label: "pem sec1 ec p256 (plain)",
        pem: """
        -----BEGIN EC PARAMETERS-----
        BggqhkjOPQMBBw==
        -----END EC PARAMETERS-----
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIMYxzVe8snkB2H8XahABDnHFUsxtHz0JWgskSXTPc26coAoGCCqGSM49
        AwEHoUQDQgAEdVPpCEmXZBwutIF5FTULRYsdiAM6KIYONzKewSiPR09zGWM8xZ2j
        k3oZx728DuDeLSog/HjHn8Y6ZgBZZIMBZw==
        -----END EC PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:Q7t9Vu1NEBGcpgT29b1a+VvqxCOMCjvSWbbZQfX/BgI",
        expectedType: .ecdsaP256
    ),
    ImportVector(
        label: "pem pkcs8 ed25519 (plain)",
        pem: """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIMq+7PKUKgu7InktQzOUAUrrxSgK5qXbzLX9yQWuKStu
        -----END PRIVATE KEY-----
        """,
        passphrase: nil,
        fingerprint: "SHA256:9piVNPSxXn/HfBg9alGX9e24g9nVqs49aJDnILj3Zy0",
        expectedType: .ed25519
    ),
    ImportVector(
        label: "pem pkcs8 rsa (encrypted)",
        pem: """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQTdoinhiQEJW1BgpN
        PSiDmgICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBz27erc7pSkBqNS
        L6wDYBsEggTQK4y/ksWEKWVqjF2gWFmulsvO00CEhsLTmmr6bccKcKPB6+FtZ3lM
        AfaVIVIy8HOvet9JVApEDBHIH/aYakUXKZ2XxbCft7ed4WNv7bLGHJFT9fpigTf8
        KSU9sYm7vi/1fHxYUw95X17pbceCqzxsvLzSjXR3gVwpjuFV3mcXSvA/o9qyodfW
        WxIrHjsP+8QA/hVRdiJN1wjlCdRqgTNuoaFsUhEz8Y3Ylgc4tq4QA8zPhNwr/Dgm
        EB9gBBM7oalz7TKunJ9Aua70bhPVVI6gAO4C2kh1kDYKJB5An6K92E9ObsHMDNtC
        RbwM7X+3IzfjulJvk5/+z2QhmsjcuYUIhk0IY5ti6Vtz0yFGGtFapE8Mu3sdx2ze
        RT1EyH6XNpy0A5E0sYaUtmPkAM0zbFRQJon778ZiqaCSBFm4CUE7qt2UeMjjNv2X
        RuLKp6kaSd+A156iZ8q6FLPmWX6Pwa9/EculZvAU0wPM7TKXE46X1KXcvToGKX5X
        CswQT+KpJBMXL9h3XuxnBSv5A/H3Lpa4y8rdpHQPs6ZK/fRxviS/Boq6lg8OajlX
        GKrYMQx0QFSFuONIaAYKKmdvY1KIhpctSGcqnH8J9l5GK/kzhrp3SZZllUQeK397
        r4RUQ2NLfdnTJrwHSbHrVktIjZ1l17Y0RRNFthwyT9B/QjAsCa1pX2cfoUKC4tIE
        H7kUhiZnsLJlTEn8etm3SJ9n36U5st/q8Y+0hS1x/a8LEsGYrQEUeNOmvv0fVNLo
        8zHQKcJENHrzj0X6y88/33pU1A4JZ+rPJV8NAwrF2rd7yrMZ+vDHwNhZJL8fFAgs
        M3VbmWMiS5hMhLYFY+FBK6Ozqrz5kHB+vU/gE5yy1GWq6RxprYVgYjqTvBklWNZb
        rtxTNdV4/s960QAW+Ei9xjQ2UKzOSP7NsYd3mGjW0oBNzE9ZEfbb5UN06oigzL7F
        +5B62Dvtb1wHqVMZdJYbVKqRRCcLHn/IzEie7e0rZi1/OXxbyIQJeKkmfHmkpz/B
        4Vly1ULxM8DTpt4eSnW0QQrQDwSda+WvbJQ/Ha1+Pm05LVH8njMIZTr9LZBmsnlz
        CF1xjoP5DlszNstO5vK/6u4apCoPG6xjl2lASJRUnYdwtXUJpO0CPAJFLQ6c6g0N
        6pXjz1wYcOgvulJ0fMQ2BrNhG7E0L8UhUU9Yylv6yfAwS/UWbOoObwuFKeiKq4X3
        wUAx/vqbeIMmRIRtA0dO9w1EYORo/aVfU4kjoTRKOdvz7H5s9RK6I2XjpNMciHWs
        CJdYHHVWbjuIrGLNRmtBY+Pg1h2r31iS3Lmc6aax2BIp9k6GnWC485anZQyQwP5Y
        Q8Mt65bUcqppVwie8ip+HHZ2DsKUUae4JL1dZDkcY8Cjnr0/5qtLrC1scF3ZBioM
        rLzktP+nh6KLMi3J0tLs9aRO3a5DLKkMsfU3TuEVSbyyYSgy8sVl5j+udsIK4JF/
        d0roI5QZDys8KZzbMDWzo17p1W0sioSdVbhF24jwyNx57DLh1fZPkEVNmlq4ucBU
        hD/roN1+VndtEwx2xYhrLL1F/M/SZ8/fKD2u3OAkuFWzJWuDE7qgplDYpsaFiaDm
        z9Aw2MqjV3MCc6AX93k/+K2UVgwRpWyiWHZ5+OQGmsQZ12OvQjPzkK4=
        -----END ENCRYPTED PRIVATE KEY-----
        """,
        passphrase: "secretpw",
        fingerprint: "SHA256:SxtBfBxd7MA/wUng/VDBRIgSKAFRHlVN1XsQlanNUMo",
        expectedType: .rsa
    ),
]

/// Encrypted OpenSSH key (bcrypt + aes256-ctr); only importable when the bcrypt component is built.
let encryptedOpenSSHVector = ImportVector(
    label: "openssh ed25519 (encrypted)",
    pem: """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBMtoYCXJ
    nnmsasrmStDIi9AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILWTkTOLd5OxFykG
    oS9Gc0qdYj9lFU/fKC2NLh42E0xuAAAAkH8pZoZjaYM/Hi9TczO0qsXrRRxzhDRpJfjzr3
    t4nG7sd0118cVDBT5B2bkltB7adFsP6L0CJIGoASWhJUBdbFN+n+ZSE06pjeqGEh8A7ZtH
    UtBPKj4hf3uzI6xXb2QojzSdcjSCiayOY1Qew6Z3AVnvelj5r1sRfLKoIwGpvxs0L0pkT/
    jKXdEANBMbFTr+Mg==
    -----END OPENSSH PRIVATE KEY-----
    """,
    passphrase: "s3cr3t-pass",
    fingerprint: "SHA256:wuKRx6v7oY3RHHrBXfYe3sWqpsATMffm4RUeQkOC6XA",
    expectedType: .ed25519
)
