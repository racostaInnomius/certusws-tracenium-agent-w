// test/plugins/eku-fixture.ts
//
// Certificado autofirmado de usar y tirar con extendedKeyUsage =
// serverAuth, clientAuth, codeSigning y keyUsage = digitalSignature,
// keyEncipherment. Generado una vez con OpenSSL 3.6.3
// (`-addext "extendedKeyUsage=serverAuth,clientAuth,codeSigning"`) y
// commiteado para que la suite no necesite openssl ni red. La clave se
// descartó al generarlo: aquí solo hace falta el certificado.
export const EKU_FIXTURE_CERT = `-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUa6+FiT4ccC4ijhzIA9Dx7LSoukAwDQYJKoZIhvcNAQEL
BQAwNTEaMBgGA1UEAwwRZWt1LWZpeHR1cmUubG9jYWwxFzAVBgNVBAoMDlRyYWNl
bml1bSBUZXN0MB4XDTI2MDkwNDAyMDc0OVoXDTM2MDkwMTAyMDc0OVowNTEaMBgG
A1UEAwwRZWt1LWZpeHR1cmUubG9jYWwxFzAVBgNVBAoMDlRyYWNlbml1bSBUZXN0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqWLpyvtbLRbsx9/Z9SIP
bGaQyXUw181fFUTA5eJ+4ccKNi9ZILEJVw2R6TnCm2JOTmX8QVtyWV9ev1jZcnKd
9YZtPSeJ9+p7rtsV7DFayT6W3P17m6SyJw2o6/Rm1plxc3WXJncf4UuajpeG1G3a
XaHQ1aFInTAqIX5gD+fzGaXu7+UI9KBFdA0HbRBKsgDstM2bqP8bw9ugpZqp+BZy
UUCVX/Ff95AW213uUDvf23wtbNcq3bi7cS9FhKDw+QYw1xETKUWikV7RRoaG5fZH
dRJ0pzC3XvlCEfx3YNTZlH3tuHEJr0vOOo081RePP7FJDFZEsxY/sYkws0SM3xgN
CwIDAQABo4GKMIGHMB0GA1UdDgQWBBR1f13tRDJ6QAUN4k+/CVrMIXe3qTAfBgNV
HSMEGDAWgBR1f13tRDJ6QAUN4k+/CVrMIXe3qTAPBgNVHRMBAf8EBTADAQH/MCcG
A1UdJQQgMB4GCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMwCwYDVR0PBAQD
AgWgMA0GCSqGSIb3DQEBCwUAA4IBAQA6EG7mG8QfIak006A9xEK6RmL0QEW1Wmpz
NPkrkffuVOfM0HfqYHVMEdtKYywgolAaj9o53lp2R77Oan1/kQiq26gb7/9DSw3s
uGjB5TQAG/wTBOPwjh0qAB1ePyiWp63uF07nZ43p8YxWVheMo7Om14t1+8qfqxfL
PDiESX02T5yIf8aWPdze05NT9ilgfei033X6ojmLTzAMNw11BAPissyayZ7kCF22
yG/f/G8j5pTkaRPDoYG5ZGGyK/h4AGD6AV+m0jTuePSafNKSDUXD+a8TbGyfs9i8
1OksDT9r3dadezhdkZ7yuuxsDIfN05zYFOJ1351mSSLEvdo5fECG
-----END CERTIFICATE-----
`;
