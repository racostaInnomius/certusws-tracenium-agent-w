// privsvc/macos/helpers/keystore/main.swift
//
// tracenium-keystore — almacen de claves NO EXTRAIBLES para macOS.
//
// ADR-0011, decision 9.b. Cierra la unica deuda de plataforma que esa
// decision dejaba abierta:
//
//   Windows  ✅ CngKey con nombre, ExportPolicy = None  (CryptoCsr.cs)
//   macOS    ⚠️ client.key.pem en disco, mode 0600      ← esto
//   Linux    fichero
//
// La frase del ADR que ordena todo lo demas: «en macOS se parte de un
// fichero, que es exportable por definicion — ahi `0600` es control de
// ACCESO, no de EXTRACCION».
//
// ── Por que un binario Swift y no el CLI `security` ─────────────────
//
// Porque se MIDIO que el camino barato no funciona. `security import`
// documenta una opcion `-x` («private keys are non-extractable after
// being imported»), y no hace nada:
//
//   $ security import id.p12 -k <kc> -x        # exit 0
//   $ security export  -k <kc> -t privKeys ... # exit 0, 1490 bytes
//   ⇒ el modulo RSA que sale es EL MISMO que entro
//
// Comprobado el 2026-08-31 con `-x`, con `-x -A` y sin nada: los tres
// exportan la clave. Es una opcion que existe en el `usage` y falla en
// silencio, que es la peor clase: se habria dado por cerrada la deuda
// con la clave igual de extraible que antes.
//
// La unica via que SI funciona es crear la clave DENTRO del llavero y no
// dejar que exista fuera nunca. Medido con esta misma API:
//
//   SecKeyCopyExternalRepresentation -> errSecDataNotAvailable (-25316)
//   SecItemExport                    -> errSecDataNotAvailable (-25316)
//   security export -t privKeys      -> «The contents of this item
//                                        cannot be retrieved»
//   SecKeyCreateSignature            -> ✅ 256 bytes: sigue firmando
//
// Es decir: exactamente la propiedad de Windows —la clave tiene nombre,
// es direccionable, es borrable, y no sale—, obtenida por la misma via
// que alli (el proveedor la guarda; nosotros solo la usamos).
//
// ── Por que el CSR se codifica a mano ───────────────────────────────
//
// Consecuencia directa de lo anterior: si la clave no sale del llavero,
// `openssl req` no puede firmarla. El PKCS#10 hay que construirlo aqui y
// firmarlo con `SecKeyCreateSignature`. No es una preferencia de estilo,
// es lo que cuesta que la clave no sea extraible.
//
// ⚠️ NADIE LLAMA A ESTO TODAVIA, y es deliberado — igual que los guards
// de la fase 1. La clave de identidad del PROPIO agente no puede mudarse
// aqui: ver la nota de crypto-store.ts sobre los cinco consumidores que
// necesitan los bytes en crudo. Este almacen es para la fase 2
// (`cdp.csr.generate`), donde las claves son nuevas y no tienen ese
// lastre.
//
// ── Contrato (una linea JSON en stdout, nada mas) ───────────────────
//
//   create  --label L [--bits N]     -> {"ok":true,"label":L,"created":true}
//   csr     --label L --subject "CN=a,O=b,OU=c"
//           [--dns d]... [--uri u]... [--eku clientAuth|serverAuth]
//                                    -> {"ok":true,"csrPem":"..."}
//   install-cert --label L --cert <fichero>
//                                    -> {"ok":true,"installed":true,"sha256":"..."}
//   info    --label L                -> {"ok":true,"exists":true,"extractable":false}
//   delete  --label L                -> {"ok":true,"deleted":N}
//
//   fallo:  {"ok":false,"code":"<codigo estable>","message":"..."}

import Foundation
import Security
import CommonCrypto

// ───────────────────────────── salida ──────────────────────────────

func emit(_ obj: [String: Any]) -> Never {
  let data = try! JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
  FileHandle.standardOutput.write(data)
  FileHandle.standardOutput.write("\n".data(using: .utf8)!)
  exit(obj["ok"] as? Bool == true ? 0 : 1)
}

func die(_ code: String, _ message: String) -> Never {
  emit(["ok": false, "code": code, "message": message])
}

// ───────────────────────────── DER ─────────────────────────────────
//
// Un codificador minimo. Solo lo que un PKCS#10 necesita: no pretende
// ser una biblioteca ASN.1, y por eso cabe entero en una pantalla y se
// puede auditar de un vistazo.

enum DER {
  /// Longitud en forma corta o larga, segun manda X.690.
  static func length(_ n: Int) -> [UInt8] {
    if n < 0x80 { return [UInt8(n)] }
    var bytes: [UInt8] = []
    var v = n
    while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
    return [UInt8(0x80 | bytes.count)] + bytes
  }

  static func tlv(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
    [tag] + length(value.count) + value
  }

  static func sequence(_ items: [[UInt8]]) -> [UInt8] { tlv(0x30, items.flatMap { $0 }) }
  static func set(_ items: [[UInt8]]) -> [UInt8] { tlv(0x31, items.flatMap { $0 }) }
  static func integer(_ v: UInt8) -> [UInt8] { tlv(0x02, [v]) }
  static func null() -> [UInt8] { [0x05, 0x00] }
  static func oid(_ raw: [UInt8]) -> [UInt8] { tlv(0x06, raw) }
  static func utf8(_ s: String) -> [UInt8] { tlv(0x0C, Array(s.utf8)) }
  static func ia5(_ s: String) -> [UInt8] { tlv(0x16, Array(s.utf8)) }
  static func octet(_ v: [UInt8]) -> [UInt8] { tlv(0x04, v) }
  static func boolTrue() -> [UInt8] { [0x01, 0x01, 0xFF] }

  /// BIT STRING con 0 bits sin usar — el caso de una firma o una SPKI.
  static func bits(_ v: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + v) }

  /// Etiqueta de contexto IMPLICITA, constructed o primitiva.
  static func context(_ n: UInt8, constructed: Bool, _ v: [UInt8]) -> [UInt8] {
    tlv(0x80 | (constructed ? 0x20 : 0x00) | n, v)
  }
}

// OIDs, en su forma DER ya codificada.
enum OID {
  static let cn: [UInt8] = [0x55, 0x04, 0x03]
  static let o: [UInt8] = [0x55, 0x04, 0x0A]
  static let ou: [UInt8] = [0x55, 0x04, 0x0B]
  static let rsaEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
  static let sha256WithRSA: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
  static let extensionRequest: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E]
  static let keyUsage: [UInt8] = [0x55, 0x1D, 0x0F]
  static let extKeyUsage: [UInt8] = [0x55, 0x1D, 0x25]
  static let subjectAltName: [UInt8] = [0x55, 0x1D, 0x11]
  static let clientAuth: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
  static let serverAuth: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
}

// ──────────────────────────── llavero ──────────────────────────────

let DEFAULT_KEYCHAIN = "/Library/Keychains/System.keychain"

func openKeychain(_ path: String) -> SecKeychain {
  var ref: SecKeychain?
  let st = SecKeychainOpen(path, &ref)
  guard st == errSecSuccess, let kc = ref else {
    die("keychain_open_failed", "no se pudo abrir \(path): OSStatus \(st)")
  }
  return kc
}

func tagData(_ label: String) -> Data { Data("com.certusws.tracenium.\(label)".utf8) }

/// Busca la clave PRIVADA por etiqueta.
///
/// ⚠️ Se filtra por `kSecAttrKeyClass`. Generar un par RSA deja DOS
/// items con el mismo tag —privada y publica—, y una consulta sin la
/// clase devuelve cualquiera de los dos.
func findKey(_ kc: SecKeychain, _ label: String, priv: Bool) -> SecKey? {
  let q: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: tagData(label),
    kSecAttrKeyClass as String: priv ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic,
    kSecMatchSearchList as String: [kc] as CFArray,
    kSecReturnRef as String: true
  ]
  var out: CFTypeRef?
  guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
  guard let ref = out, CFGetTypeID(ref) == SecKeyGetTypeID() else { return nil }
  return (ref as! SecKey)
}

// ──────────────────────────── comandos ─────────────────────────────

func cmdCreate(kc: SecKeychain, label: String, bits: Int) -> Never {
  if findKey(kc, label, priv: true) != nil {
    emit(["ok": true, "label": label, "created": false])
  }
  var err: Unmanaged<CFError>?
  let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: bits,
    kSecAttrIsPermanent as String: true,
    // La linea entera de este fichero. Sin ella la clave es exportable
    // y esto no seria mejor que el PEM en disco que viene a sustituir.
    kSecAttrIsExtractable as String: false,
    kSecAttrLabel as String: label,
    kSecAttrApplicationTag as String: tagData(label),
    kSecUseKeychain as String: kc
  ]
  guard SecKeyCreateRandomKey(attrs as CFDictionary, &err) != nil else {
    die("key_create_failed", String(describing: err!.takeRetainedValue()))
  }
  emit(["ok": true, "label": label, "created": true, "bits": bits])
}

/// Enumera las claves del almacen bajo un prefijo.
///
/// Existe por la decision 9.d: «una clave pendiente sin certificado es un
/// item de primera clase del inventario». La cautela que la motiva sale
/// de este mismo repositorio —`purge_after` se escribe y no lo barre
/// nadie—, asi que el respaldo no puede ser solo un cron: tiene que
/// poder MIRARSE. Sin enumeracion no hay nada que mirar.
///
/// ⚠️ NO devuelve fecha de creacion, y no por olvido: un llavero de
/// FICHERO no la guarda para las claves. Se comprobo que atributos
/// devuelve `SecItemCopyMatching` y la lista es
/// `atag bsiz class decr drve encr esiz kcls klbl labl perm sign type
/// unwp vrfy wrap` — no hay `cdat`. La edad, que es lo que de verdad
/// pregunta el operador («¿hay alguna huerfana que lleve demasiado?»),
/// la lleva el registro del lado TS, que ademas puede decir POR QUE
/// existe la clave. Esta lista es la fuente de verdad de QUE hay.
func cmdList(kc: SecKeychain, prefix: String) -> Never {
  let q: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    kSecMatchSearchList as String: [kc] as CFArray,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true
  ]
  var out: CFTypeRef?
  let st = SecItemCopyMatching(q as CFDictionary, &out)
  if st == errSecItemNotFound { emit(["ok": true, "keys": []]) }
  guard st == errSecSuccess, let filas = out as? [[String: Any]] else {
    die("list_failed", "OSStatus \(st)")
  }

  let completo = "com.certusws.tracenium.\(prefix)"
  var keys: [[String: Any]] = []
  for fila in filas {
    guard let tag = fila[kSecAttrApplicationTag as String] as? Data,
          let texto = String(data: tag, encoding: .utf8),
          texto.hasPrefix(completo) else { continue }
    keys.append(["label": String(texto.dropFirst("com.certusws.tracenium.".count))])
  }
  emit(["ok": true, "keys": keys])
}

/**
 * Instala el certificado firmado y lo ata a la clave que ya existe.
 *
 * ADR-0011 fase 3 (`cdp.cert.install`). En macOS «atar» no es una
 * operacion explicita: se añade el certificado al MISMO llavero y el
 * sistema lo empareja con la clave privada por el hash de la clave
 * publica, formando una identidad.
 *
 * ⚠️ Por eso se VERIFICA que la identidad se formo, en vez de dar por
 * buena la insercion. Si el certificado no corresponde a esta clave
 * —otro CSR, otra peticion, un cruce en el control plane— el `SecItemAdd`
 * sale con exito igual y lo unico que queda es un certificado suelto en
 * el llavero: la instalacion habria «funcionado» sin que nada use nunca
 * esa clave.
 *
 * NO se tocan trust settings ni el llavero de anclas: aqui solo entra
 * una hoja. Otorgar confianza es la amenaza que ADR-0011 gobierna, y la
 * decision 1 la deja fuera por construccion.
 */
func cmdInstallCert(kc: SecKeychain, label: String, certPath: String) -> Never {
  guard let priv = findKey(kc, label, priv: true) else {
    die("key_not_found", "no hay clave con etiqueta \(label)")
  }
  guard let datos = FileManager.default.contents(atPath: certPath) else {
    die("bad_request", "no se pudo leer el certificado en \(certPath)")
  }

  // Se acepta PEM o DER: el llamante escribe lo que le llego del control
  // plane y no tiene por que normalizarlo.
  var der = datos
  if let texto = String(data: datos, encoding: .utf8), texto.contains("BEGIN CERTIFICATE") {
    let cuerpo = texto
      .components(separatedBy: "-----BEGIN CERTIFICATE-----").last?
      .components(separatedBy: "-----END CERTIFICATE-----").first?
      .replacingOccurrences(of: "\n", with: "")
      .replacingOccurrences(of: "\r", with: "") ?? ""
    guard let d = Data(base64Encoded: cuerpo) else {
      die("bad_request", "el PEM no decodifica")
    }
    der = d
  }

  guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
    die("bad_request", "el certificado no parsea")
  }

  // La clave publica del certificado tiene que ser la de NUESTRA clave.
  // Se comprueba antes de escribir nada: es la diferencia entre «no se
  // instalo» y «se instalo algo que no sirve».
  guard let pubCert = SecCertificateCopyKey(cert),
        let pubNuestra = SecKeyCopyPublicKey(priv) else {
    die("cert_key_mismatch", "no se pudo comparar la clave publica")
  }
  var e1: Unmanaged<CFError>?
  var e2: Unmanaged<CFError>?
  let a = SecKeyCopyExternalRepresentation(pubCert, &e1) as Data?
  let b = SecKeyCopyExternalRepresentation(pubNuestra, &e2) as Data?
  guard let ra = a, let rb = b, ra == rb else {
    die("cert_key_mismatch", "el certificado no corresponde a la clave \(label)")
  }

  let st = SecItemAdd([
    kSecClass as String: kSecClassCertificate,
    kSecValueRef as String: cert,
    kSecUseKeychain as String: kc
  ] as CFDictionary, nil)
  // errSecDuplicateItem (-25299) es exito: reinstalar el mismo
  // certificado no es un fallo, y tratarlo como tal haria que un
  // reintento del job pareciera roto.
  if st != errSecSuccess && st != errSecDuplicateItem {
    die("cert_install_failed", "SecItemAdd: OSStatus \(st)")
  }

  // ¿Se formo la identidad? Es la unica pregunta que importa.
  var salida: CFTypeRef?
  let q: [String: Any] = [
    kSecClass as String: kSecClassIdentity,
    kSecMatchSearchList as String: [kc] as CFArray,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnRef as String: true
  ]
  var atada = false
  if SecItemCopyMatching(q as CFDictionary, &salida) == errSecSuccess,
     let ids = salida as? [SecIdentity] {
    for id in ids {
      var c: SecCertificate?
      if SecIdentityCopyCertificate(id, &c) == errSecSuccess, let c = c,
         (SecCertificateCopyData(c) as Data) == der {
        atada = true
        break
      }
    }
  }
  if !atada {
    die("identity_not_formed", "el certificado entro pero no quedo atado a la clave")
  }

  let sha = SecCertificateCopyData(cert) as Data
  emit([
    "ok": true,
    "label": label,
    "installed": true,
    "subject": (SecCertificateCopySubjectSummary(cert) as String?) ?? "",
    "sha256": sha256Hex(sha)
  ])
}

/// SHA-256 en hexadecimal, sin depender de CryptoKit.
func sha256Hex(_ d: Data) -> String {
  var hash = [UInt8](repeating: 0, count: 32)
  d.withUnsafeBytes { buf in
    _ = CC_SHA256(buf.baseAddress, CC_LONG(d.count), &hash)
  }
  return hash.map { String(format: "%02x", $0) }.joined()
}

func cmdInfo(kc: SecKeychain, label: String) -> Never {
  guard let key = findKey(kc, label, priv: true) else {
    emit(["ok": true, "exists": false])
  }
  // Se COMPRUEBA que no sale, en vez de confiar en que se creo bien.
  // Es el mismo intento que hace un atacante, y la unica respuesta que
  // vale es la que da la propia API.
  var err: Unmanaged<CFError>?
  let salio = SecKeyCopyExternalRepresentation(key, &err) != nil
  emit(["ok": true, "exists": true, "extractable": salio])
}

func cmdDelete(kc: SecKeychain, label: String) -> Never {
  // Bucle, no una llamada. `SecItemDelete` sobre un llavero de fichero
  // se lleva UNA coincidencia por llamada, y un par RSA son dos items:
  // una sola llamada devuelve exito dejando la clave privada dentro.
  // Ese falso verde se midio antes de escribir esto.
  var borrados = 0
  while borrados < 32 {
    let st = SecItemDelete([
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData(label),
      kSecMatchSearchList as String: [kc] as CFArray
    ] as CFDictionary)
    if st != errSecSuccess { break }
    borrados += 1
  }
  // Se verifica el resultado. La destruccion es una fase obligatoria del
  // ciclo (decision 9.c) y «devolvio exito» no es lo mismo que «ya no
  // esta».
  let queda = findKey(kc, label, priv: true) != nil
  if queda { die("key_delete_incomplete", "la clave privada sigue en el llavero tras \(borrados) borrados") }
  emit(["ok": true, "deleted": borrados])
}

// ─────────────────────────── CSR (PKCS#10) ─────────────────────────

/// SubjectPublicKeyInfo a partir de la clave publica.
///
/// La publica SI es extraible —lo es por definicion, no es un descuido—
/// y sale en formato PKCS#1, que es justo el contenido del BIT STRING.
func spki(_ pub: SecKey) -> [UInt8] {
  var err: Unmanaged<CFError>?
  guard let raw = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
    die("public_key_unavailable", String(describing: err!.takeRetainedValue()))
  }
  return DER.sequence([
    DER.sequence([DER.oid(OID.rsaEncryption), DER.null()]),
    DER.bits([UInt8](raw))
  ])
}

/// Name a partir de "CN=a,O=b,OU=c".
///
/// Se parte solo por comas de primer nivel; un DN con comas escapadas no
/// se soporta y se rechaza en vez de codificarse mal — un subject
/// silenciosamente distinto del pedido es peor que un fallo.
func name(_ subject: String) -> [UInt8] {
  var rdns: [[UInt8]] = []
  for parte in subject.split(separator: ",") {
    let kv = parte.split(separator: "=", maxSplits: 1)
    guard kv.count == 2 else { die("bad_subject", "componente invalido: \(parte)") }
    let clave = kv[0].trimmingCharacters(in: .whitespaces).uppercased()
    let valor = kv[1].trimmingCharacters(in: .whitespaces)
    let tipo: [UInt8]
    switch clave {
    case "CN": tipo = OID.cn
    case "O": tipo = OID.o
    case "OU": tipo = OID.ou
    default: die("bad_subject", "atributo no soportado: \(clave) (solo CN, O, OU)")
    }
    rdns.append(DER.set([DER.sequence([DER.oid(tipo), DER.utf8(valor)])]))
  }
  guard !rdns.isEmpty else { die("bad_subject", "subject vacio") }
  return DER.sequence(rdns)
}

func extensionsAttribute(dns: [String], uri: [String], eku: [UInt8]) -> [UInt8] {
  var exts: [[UInt8]] = []

  // keyUsage critica = digitalSignature (bit 0): 7 bits sin usar.
  exts.append(DER.sequence([
    DER.oid(OID.keyUsage), DER.boolTrue(), DER.octet([0x03, 0x02, 0x07, 0x80])
  ]))

  exts.append(DER.sequence([
    DER.oid(OID.extKeyUsage), DER.octet(DER.sequence([DER.oid(eku)]))
  ]))

  var generales: [[UInt8]] = []
  // GeneralName: dNSName es [2] IMPLICIT IA5String, uniformResourceIdentifier [6].
  for d in dns { generales.append(DER.context(2, constructed: false, Array(d.utf8))) }
  for u in uri { generales.append(DER.context(6, constructed: false, Array(u.utf8))) }
  if !generales.isEmpty {
    exts.append(DER.sequence([
      DER.oid(OID.subjectAltName), DER.octet(DER.sequence(generales))
    ]))
  }

  return DER.sequence([
    DER.oid(OID.extensionRequest),
    DER.set([DER.sequence(exts)])
  ])
}

func cmdCsr(kc: SecKeychain, label: String, subject: String, dns: [String], uri: [String], eku: [UInt8]) -> Never {
  guard let priv = findKey(kc, label, priv: true) else {
    die("key_not_found", "no hay clave con etiqueta \(label)")
  }
  guard let pub = SecKeyCopyPublicKey(priv) else {
    die("public_key_unavailable", "no se pudo derivar la clave publica")
  }

  let cri = DER.sequence([
    DER.integer(0),
    name(subject),
    spki(pub),
    // attributes es [0] IMPLICIT SET OF Attribute. Va SIEMPRE, aunque
    // sea vacio: es obligatorio en la estructura, no opcional.
    DER.context(0, constructed: true, extensionsAttribute(dns: dns, uri: uri, eku: eku))
  ])

  var err: Unmanaged<CFError>?
  guard let firma = SecKeyCreateSignature(
    priv, .rsaSignatureMessagePKCS1v15SHA256, Data(cri) as CFData, &err
  ) as Data? else {
    die("sign_failed", String(describing: err!.takeRetainedValue()))
  }

  let csr = DER.sequence([
    cri,
    DER.sequence([DER.oid(OID.sha256WithRSA), DER.null()]),
    DER.bits([UInt8](firma))
  ])

  let b64 = Data(csr).base64EncodedString()
  var pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
  var i = b64.startIndex
  while i < b64.endIndex {
    let j = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
    pem += b64[i..<j] + "\n"
    i = j
  }
  pem += "-----END CERTIFICATE REQUEST-----\n"
  emit(["ok": true, "csrPem": pem, "label": label])
}

// ──────────────────────────── argumentos ───────────────────────────

var args = Array(CommandLine.arguments.dropFirst())
guard let comando = args.first else {
  die("usage", "uso: tracenium-keystore <create|csr|info|delete> --label L [...]")
}
args = Array(args.dropFirst())

func opt(_ nombre: String) -> String? {
  guard let i = args.firstIndex(of: "--\(nombre)"), i + 1 < args.count else { return nil }
  return args[i + 1]
}

/// Todas las apariciones de una opcion.
///
/// Un certificado de servidor lleva varios nombres —el FQDN, el alias
/// corto, a veces un comodin—, asi que `--dns` y `--uri` se repiten. Una
/// sola aparicion habria obligado a inventar un separador y a lidiar con
/// el nombre que lo contenga.
func opts(_ nombre: String) -> [String] {
  var out: [String] = []
  var i = 0
  while i < args.count - 1 {
    if args[i] == "--\(nombre)" { out.append(args[i + 1]); i += 2 } else { i += 1 }
  }
  return out
}

let keychain = openKeychain(opt("keychain") ?? DEFAULT_KEYCHAIN)

// `list` es el unico que NO opera sobre una clave concreta: pregunta por
// las que hay. Se resuelve antes de exigir --label.
if comando == "list" {
  cmdList(kc: keychain, prefix: opt("prefix") ?? "")
}

guard let label = opt("label") else { die("usage", "--label es obligatorio") }

switch comando {
case "create":
  cmdCreate(kc: keychain, label: label, bits: Int(opt("bits") ?? "2048") ?? 2048)
case "info":
  cmdInfo(kc: keychain, label: label)
case "delete":
  cmdDelete(kc: keychain, label: label)
case "install-cert":
  guard let cert = opt("cert") else { die("usage", "--cert es obligatorio") }
  cmdInstallCert(kc: keychain, label: label, certPath: cert)
case "csr":
  guard let subject = opt("subject") else { die("usage", "--subject es obligatorio") }
  let eku = (opt("eku") == "serverAuth") ? OID.serverAuth : OID.clientAuth
  cmdCsr(kc: keychain, label: label, subject: subject, dns: opts("dns"), uri: opts("uri"), eku: eku)
default:
  die("usage", "comando desconocido: \(comando)")
}
