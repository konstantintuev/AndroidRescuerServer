import MySQL
import PerfectHTTP
import PerfectFastCGI
import Foundation
import Turnstile
import Dispatch
import TurnstileCrypto
import PerfectLib
import Swift
import PerfectSMTP
import LinuxBridge
import PerfectCURL
var routes = Routes()

let Host = "127.0.0.1"
let User = "admin"
let Password = "12345678"
let Database = "location_users"


private func executeShell(command: String, arguments: [String] = []) -> String? {
    let task = Process()
    task.launchPath = command
    task.arguments = arguments

    let pipe = Pipe()
    task.standardOutput = pipe
    task.launch()

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output: String? = String(data: data, encoding: String.Encoding.utf8)

    return output
}


extension String {
    func removeSpecialCharsFromString() -> String {
        let okayChars : Set<Character> =
                Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLKMNOPQRSTUVWXYZ1234567890+".characters)
        return String(characters.filter {okayChars.contains($0) })
    }
}

extension Character
{
    func unicodeScalarCodePoint() -> UnicodeScalar
    {
        let characterString = String(self)
        let scalars = characterString.unicodeScalars

        return scalars[scalars.startIndex]
    }
}


extension MySQL {
    public func secureQuery(statement: String, params: [String] = [String()]) -> MySQLStmt? {
        let mySQL = MySQLStmt(self)
        if !mySQL.prepare(statement: statement) {
            return nil
        }
        for param in params {
            mySQL.bindParam(param)
        }
        if !mySQL.execute() {
            return nil
        }
        return mySQL
    }
}


let dateErrorFormatter : DateFormatter = DateFormatter()
dateErrorFormatter.dateFormat = "dd/MM/yyyy HH:mm:ss"
class errors {

    class func sendNotificationToAdmin(title: String, body: String, error: Bool = true) {
        let message = "{\"url\":\"serveadmin://\(error ? "error" : "support")\",\"body\":\"\(body)\",\"title\":\"\(title)\",\"type\":\"link\",\"email\":\"kosiomt@gmail.com\"}"
        let url = "https://api.pushbullet.com/v2/pushes"
        CURLRequest.init(url, CURLRequest.Option.addHeader(.contentType, "application/json"), CURLRequest.Option.addHeader(.custom(name: "Access-Token"), "o.JJaZwxbxVMffqTueDZ2dDiq1IwwqadCw"), CURLRequest.Option.httpMethod(HTTPMethod.post), CURLRequest.Option.postString(message)).perform{confirmation in}
    }

    class func fcmCommunication(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String) {
        genericError(resp, result: "Communication between server and android device failed.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func userAdding(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String) {
        genericError(resp, result: "Failure adding user.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func phoneRegistrationDoneAlready(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Phone already registered.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func phoneRegistration(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Phone not registered.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func wayTooGenericError(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Error acquired!\nTry again.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func mailSending(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Email not sent.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func dataServerConnection(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Failure connecting to data server.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    class func wrongPassword(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Wrong password!", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    static func genericError(_ resp: HTTPResponse?, result: String, phone: String?, reqPhone: String?, request: HTTPRequest?, log: String, caller: String, _ response_code: HTTPResponseStatus = HTTPResponseStatus.internalServerError) {
        if resp != nil {
            let json = "{" +
                    "\"result\": \"\(result)\"," +
                    "\"error\": true" +
                    "}"
            resp!.setBody(string: json)
            resp!.completed(status: response_code)
        }
        let date = dateErrorFormatter.string(from: Date())

        if !log.isEmpty {
            let err1 = "\(date) ERR: \(request == nil ? "" : "url: \(request!.uri)") "
            let err2 = "\(phone == nil ? "" : " userPhone=\(phone!)\n")\(reqPhone == nil ? "" : " requiredPhone=\(reqPhone!)\n") caller: \(caller)\n\(request == nil ? "" : " userIP=\(request!.remoteAddress.host)\n")log: \(log)"
            let dataMysql = MySQL()
            if dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
                _ = dataMysql.secureQuery(statement: "INSERT INTO `error_log_database` (`id`, `text`, `description`) VALUES (NULL, ?, ?)", params: [err1, err2 + "\n" + err1])
            }
            sendNotificationToAdmin(title: "ERROR", body: err1)
            print(err1+" "+err2)
        }
    }

    static func processingData(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Error processing data.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }
    static func internalServer(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Internal server error.", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }
    static func passwordVerification(_ resp: HTTPResponse?, phone: String? = nil, reqPhone: String? = nil, request: HTTPRequest? = nil, log: String = "") {
        genericError(resp, result: "Couldn't verify your password!", phone: phone, reqPhone: reqPhone, request: request, log: log, caller: #function)
    }

    static func activeOneDay(_ resp: HTTPResponse?) {
        genericError(resp, result: "The code is active one calendar day!\nThe code given is now inactive.", phone: nil, reqPhone: nil, request: nil, log: "", caller: #function)
    }
    static func verificationCodeWrongTries(_ resp: HTTPResponse?, numberTries: inout Int) -> Bool {
        numberTries += 1
        if (numberTries > 3) {
            genericError(resp, result: "Too many wrong codes entered!\nThe code given is now inactive.", phone: nil, reqPhone: nil, request: nil, log: "", caller: #function)
            return false
        } else {
            genericError(resp, result: "\(numberTries)/3 tries!", phone: nil, reqPhone: nil, request: nil, log: "", caller: #function)
            return true
        }
    }
}
let dateFormatter: DateFormatter = DateFormatter()
dateFormatter.dateFormat = "dd.MM.yy"
let calendar = Calendar.current
func success(_ resp: HTTPResponse, message: String = "Success!") {
    let json = "{" +
            "\"result\": \"\(message)\"," +
            "\"error\": false" +
            "}"
    resp.setBody(string: json)
    resp.completed()
}

func indexHandler(request: HTTPRequest, _ response: HTTPResponse) {
    response.appendBody(string: "Index handler: You accessed path \(request.path)")
    response.completed()
}

routes.add(method: .get, uris: ["/", "index.html"], handler: indexHandler)

routes.add(method: .post, uri: "/server/addusr") {
    req, resp in

    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var pass = ""
        var mail = ""
        var fcm_token = "NULL"
        var test = false
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                pass = json["pass"] as? String ?? ""
                phone = json["phone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
                mail = json["mail"] as? String ?? ""
                if json["fcm_token"] != nil {
                    fcm_token = "'\(json["fcm_token"] as? String ?? "")'"
                }
            } else {
                errors.processingData(resp, request: req, log: "json nil")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var notFound = false

        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM `location_users\(testAdd)` WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(nil, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            notFound = true
        }
        if !notFound {
            if let results: MySQLStmt.Results = dataSql?.results(), results.numRows > 0 {
                var first = true
                results.forEachRow { result in
                    if (first) {
                        first = false
                        if result.isEmpty || result[0] == nil {
                            notFound = true
                        } else {
                            notFound = false
                        }
                    }
                }
            } else {
                notFound = true
            }
        }
        if (!notFound) {
            errors.phoneRegistrationDoneAlready(resp)
            return
        } else {
            let password = BCrypt.hash(password: pass)

            var ress: MySQLStmt.Results?
            if dataMysql.secureQuery(statement: "INSERT INTO `location_users\(testAdd)` (`id`, `phone`, `pass`, `mail`, `lat`, `long`, `fcm_token`) VALUES(NULL, ?, ?, ?, NULL, NULL, ?)", params: [phone, password, mail, fcm_token]) == nil {
                errors.userAdding(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
                return
            } else {
                let json = "{" +
                        "\"result\": \"User added!\"," +
                        "\"error\": false" +
                        "}"
                resp.setBody(string: json)
                resp.completed()
                return
            }
        }
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
        return
    }
}

routes.add(method: .post, uri: "/server/getusr") {
    req, resp in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var pass = ""
        var test = false
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                pass = json["pass"] as? String ?? ""
                phone = json["phone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
            } else {
                errors.processingData(resp, request: req, log: "nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var notFound = false

        var ress: MySQLStmt.Results?

        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM `location_users\(testAdd)` WHERE phone = ?", params: [phone])
        if dataMysql == nil {
            errors.dataServerConnection(nil, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            notFound = true
        } else {
            ress = dataSql?.results()
        }
        if !notFound {
            if let results = ress, results.numRows > 0 {
                print(results.numRows)
                results.forEachRow { result in
                    print(result)
                    if result.isEmpty || result[0] == nil {
                        notFound = true
                    } else {
                        if let passHash = result[2], let mail = result[3], !mail.isEmpty {
                            do {
                                if try BCrypt.verify(password: pass, matchesHash: passHash) {
                                    let json = "{" +
                                            "\"result\": \"\(mail)\"," +
                                            "\"error\": false" +
                                            "}"
                                    resp.setBody(string: json)
                                    resp.completed()
                                } else {
                                    errors.wrongPassword(resp)
                                    return
                                }
                            } catch {
                                errors.passwordVerification(resp, phone: phone, request: req, log: "Bcrypt error: \(error) passGiven: \(pass)")
                                return
                            }
                        } else {
                            let mail = result[3]
                            errors.wayTooGenericError(resp, phone: phone, request: req, log: "password: \(result[2] != nil ? "not nil" : "nil"), mail: \(mail != nil && !mail!.isEmpty ? "not nil and not empty" : "nil or empty")")
                            return
                        }
                    }
                }
            } else {
                notFound = true
            }
        }
        if (notFound) {
            errors.phoneRegistration(resp)
            return
        }
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
        return
    }
}

routes.add(Route(method: .post, uri: "/server/forgotpass", handler: { (req, resp) -> () in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var codeGiven: String? = nil
        var newPass: String? = nil
        var test = false
        var except = false
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                phone = json["phone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
                codeGiven = json["code"] as? String
                newPass = json["newPass"] as? String
            } else {
                errors.processingData(resp, request: req, log: "nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        var ress: MySQLStmt.Results?
        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM location_users\(testAdd) WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        ress = dataSql?.results()
        if let results: MySQLStmt.Results = ress, results.numRows > 0 {
            results.forEachRow { result in
                if result.isEmpty {
                    errors.dataServerConnection(resp, phone: phone, request: req, log: "Result empty.")
                    return
                }
                if let mailRes = result[3] {

                    var ress: MySQLStmt.Results?
                    let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM verification_codes\(testAdd) WHERE phone = ?", params: [phone])

                    if dataSql == nil {
                        errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
                        return
                    }

                    ress = dataSql?.results()

                    var phoneIsThere = false;
                    var res: MySQL.Results.Element?

                    if let results: MySQLStmt.Results = ress, results.numRows > 0 {
                        results.forEachRow { result in
                            res = result
                            if !result.isEmpty && result[0] != nil {
                                phoneIsThere = true;
                            }
                        }
                    }
                    if !phoneIsThere {
                        do {
                            let client = SMTPClient(url: "smtps://smtp.zoho.eu:465", username: "support@androidrescuer.cf", password: "KosioPHP4$")
                            var email = EMail(client: client)

                            email.subject = "Android Rescuer Verification Code"

                            email.from = Recipient(name: "Android Rescuer", address: "support@androidrescuer.cf")

                            var code = ""
                            srandom(UInt32(time(nil)))
                            code = String(format: "%04d", UInt32(random() % 10000))
                            var failed = 0
                            var ress: MySQLStmt.Results?
                            while dataMysql.secureQuery(statement: "INSERT INTO `verification_codes\(testAdd)` (`phone`, `code`, `auth_time`, `tries`) VALUES (?, ?, ?, '0')", params: [phone, code, dateFormatter.string(from: Date())]) == nil && failed < 5 {
                                failed += 1
                                srandom(UInt32(time(nil)))
                                code = String(format: "%04d", UInt32(random() % 10000))
                            }
                            email.html = "<h1>Verification Code</h1>" +
                                    "<h2>The CODE: \(code)</h2>" +
                                    "<h3>Write this code in the Android Rescuer app forgotten password dialog.</h3>"

                            email.to.append(Recipient(name: "Receiver", address: mailRes))

                            try email.send { code, header, body in
                                /// response info from mail server
                                if code >= 0 && code <= 399 {
                                    let json = "{" +
                                            "\"result\": \"Email sent!\"," +
                                            "\"error\": false" +
                                            "}"
                                    resp.setBody(string: json)
                                    resp.completed()
                                    return
                                } else {
                                    errors.mailSending(resp, phone: phone, request: req, log: "Mail sending error: not success response code: \(code).\nHeader: \(header),\nBody: \(body)")
                                    return
                                }
                            }//end send
                        } catch (let err) {
                            errors.mailSending(resp, phone: phone, request: req, log: "Mail sending error: \(err)")
                            return
                        }
                    } else {
                        var codeNeeded: String?
                        var tries = 0;

                        if let result = res {
                            if !result.isEmpty && result[0] != nil {
                                codeNeeded = result[1]
                                tries = Int(result[3]!) ?? 0
                                if let authDate = dateFormatter.date(from: result[2]!) {
                                    let componentsAuth = calendar.dateComponents([Calendar.Component.year, Calendar.Component.month, Calendar.Component.day], from: authDate)
                                    let componentsNow = calendar.dateComponents([Calendar.Component.year, Calendar.Component.month, Calendar.Component.day], from: Date())
                                    if componentsAuth.year! != componentsNow.year! || componentsAuth.month! != componentsNow.month! || componentsAuth.day! != componentsNow.day! {
                                        var ress: MySQLStmt.Results?
                                        _ = dataMysql.secureQuery(statement: "DELETE FROM `verification_codes\(testAdd)` WHERE `verification_codes\(testAdd)`.`phone` = ? AND `verification_codes\(testAdd)`.`code` = ?", params: [phone, codeNeeded!])
                                        errors.activeOneDay(resp)
                                        return
                                    }
                                }
                            }
                        }
                        if (codeGiven != nil && codeNeeded != nil && codeNeeded! == codeGiven!) {
                            if newPass != nil, let id = result[0] {
                                let password = BCrypt.hash(password: newPass!)
                                let sql = "UPDATE `location_users\(testAdd)` SET `pass` = ? WHERE `location_users\(testAdd)`.`id` = ?"
                                var ress: MySQLStmt.Results?
                                if dataMysql.secureQuery(statement: sql, params: [password, id]) == nil {
                                    errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
                                    return
                                }
                                let json = "{" +
                                        "\"result\": \"Password changed!\"," +
                                        "\"error\": false" +
                                        "}"
                                resp.setBody(string: json)
                                _ = dataMysql.secureQuery(statement: "DELETE FROM `verification_codes\(testAdd)` WHERE `verification_codes\(testAdd)`.`phone` = ? AND `verification_codes\(testAdd)`.`code` = ?", params: [phone, codeNeeded!])
                                resp.completed()
                            } else {
                                errors.wayTooGenericError(resp, phone: phone, request: req, log: "newPass value: \(newPass != nil ? "not nil" : "nil"), id: \(result[0] != nil ? "not nil" : "nil")")
                                return
                            }

                        } else {
                            var ress: MySQLStmt.Results?
                            if !errors.verificationCodeWrongTries(resp, numberTries: &tries) {
                                _ = dataMysql.secureQuery(statement: "DELETE FROM `verification_codes\(testAdd)` WHERE `verification_codes\(testAdd)`.`phone` = ? AND `verification_codes\(testAdd)`.`code` = ?",
                                        params: [phone, codeNeeded!])
                            } else {
                                _ = dataMysql.secureQuery(statement: "UPDATE `verification_codes\(testAdd)` SET `tries` = ? WHERE `verification_codes\(testAdd)`.`phone` = ? AND `verification_codes\(testAdd)`.`code` = ?",
                                        params: [String(tries), phone, codeNeeded!])
                            }
                            return
                        }
                    }
                } else {
                    errors.dataServerConnection(resp, phone: phone, request: req, log: "Result[3] value nil")
                    return
                }
            }
        } else {
            errors.phoneRegistration(resp)
            return
        }
        dataMysql.close()
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
        return
    }
}))

routes.add(Route(method: .post, uri: "/server/updatetoken", handler: { (req, resp) -> () in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var pass = ""
        var phone = ""
        var test = false
        var token = ""
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                pass = json["pass"] as? String ?? ""
                phone = json["myphone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
                token = json["token"] as? String ?? ""
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }

        var ress: MySQLStmt.Results?
        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM location_users\(testAdd) WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        ress = dataSql?.results()

        //store complete result set
        if let results: MySQLStmt.Results = ress, results.numRows > 0 {
            results.forEachRow { item in
                if let pass1 = item[2], let id = item[0] {
                    do {
                        if try BCrypt.verify(password: pass, matchesHash: pass1) {
                            let insertAuth = "UPDATE `location_users\(testAdd)` SET `fcm_token` = '\(token)' WHERE `location_users\(testAdd)`.`id` = ?"
                            var ress: MySQLStmt.Results?
                            if dataMysql.secureQuery(statement: insertAuth, params: [id]) != nil {
                                success(resp)
                            } else {
                                errors.dataServerConnection(resp, phone: phone, request: req, log: "Insert user query failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
                                return
                            }
                        } else {
                            errors.wrongPassword(resp)
                            return
                        }
                    } catch {
                        errors.passwordVerification(resp, phone: phone, request: req, log: "Bcrypt error: \(error) passGiven: \(pass)")
                        return
                    }
                } else {
                    errors.wayTooGenericError(resp, phone: phone, request: req, log: "password: \(item[2] != nil ? "not nil" : "nil"), id: \(item[0] != nil ? "not nil" : "nil")")
                    return
                }
            }
        } else {
            errors.internalServer(resp, phone: phone, request: req, log: "results nil or field 0")
            return
        }
        dataMysql.close()
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
    }
}))

routes.add(Route(method: .post, uri: "/server/updaloc", handler: { (req, resp) -> () in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var pass = ""
        var phone = ""
        var test = false
        var lat = 0.0
        var long = 0.0
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                pass = json["pass"] as? String ?? ""
                phone = json["phone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
                lat = json["lat"] as? Double ?? 0.0
                long = json["long"] as? Double ?? 0.0
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }

        var ress: MySQLStmt.Results?
        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM location_users\(testAdd) WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        ress = dataSql?.results()

        //store complete result set
        if let results: MySQLStmt.Results = ress, results.numRows > 0 {
            results.forEachRow { item in
                if let pass1 = item[2], let id = item[0] {
                    do {
                        if try BCrypt.verify(password: pass, matchesHash: pass1) {
                            let insertAuth = "UPDATE `location_users\(testAdd)` SET `lat` = '\(lat)', `long` = '\(long)' WHERE `location_users\(testAdd)`.`id` = ?"
                            var ress: MySQLStmt.Results?
                            if dataMysql.secureQuery(statement: insertAuth, params: [id]) != nil {
                                success(resp)
                            } else {
                                errors.dataServerConnection(resp, phone: phone, request: req, log: "Insert user query failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
                                return
                            }
                        } else {
                            errors.wrongPassword(resp)
                            return
                        }
                    } catch {
                        errors.passwordVerification(resp, phone: phone, request: req, log: "Bcrypt error: \(error) passGiven: \(pass)")
                        return
                    }
                } else {
                    errors.wayTooGenericError(resp, phone: phone, request: req, log: "password: \(item[2] != nil ? "not nil" : "nil"), id: \(item[0] != nil ? "not nil" : "nil")")
                    return
                }
            }
        } else {
            errors.internalServer(resp, phone: phone, request: req, log: "results nil or fields 0")
            return
        }
        dataMysql.close()
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
    }
}))

routes.add(Route(method: .post, uri: "/server/sendcontrol", handler: { (req, resp) -> () in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var pass = ""
        var test = false
        var data = ""
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                phone = json["phone"] as? String ?? ""
                pass = json["pass"] as? String ?? ""
                data = json["data"] as? String ?? ""
                test = json["test"] as? Bool ?? false
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure connecting to data server \(Host)")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }

        print("testadd: \(testAdd) phone: \(phone)")

        var ress: MySQLStmt.Results?

        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM location_users\(testAdd) WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        ress = dataSql?.results()

        if let results: MySQLStmt.Results = ress, results.numRows > 0 {
            var first = true
            results.forEachRow { item in
                if first {
                    first = false
                    do {
                        if let passInDB = item[2] {
                            if try BCrypt.verify(password: pass, matchesHash: passInDB) {
                                let fcm_token = item[6]!
                                let message = "{" +
                                        "\"data\": {" +
                                        data +
                                        "}," +
                                        "\"to\" : \"\(fcm_token)\"" +
                                        "}"
                                let url = "https://fcm.googleapis.com/fcm/send"
                                CURLRequest.init(url, CURLRequest.Option.addHeader(.contentType, "application/json"), CURLRequest.Option.addHeader(.authorization, "key=AAAAXpJU92g:APA92bSwwiGPZ-CG2oC73dJa7dI139pIdk7ZpasGhnUJ2BC7Rcz2YgeyAnzfuHTX3Qiue-54m-tBs_owfwagPW1lGic3nmRvzLanjyEeMRI1JN1io-AZl-zkbUhbMAOTWYK3d9GFu9z5"), CURLRequest.Option.httpMethod(HTTPMethod.post), CURLRequest.Option.postString(message)).perform {
                                    confirmation in
                                    do {
                                        let response = try confirmation()
                                        if (response.responseCode != 200) {
                                            errors.internalServer(resp, log: "Failed: response code \(response.responseCode)")
                                            return
                                        }
                                        var fcm_error = false
                                        var fcm_er = ""
                                        let bodyJSON = response.bodyJSON
                                        if let res = bodyJSON["results"] as? [Any] {
                                            for item1 in res {
                                                if let item = (item1 as? [String: Any] ?? [:]).first {
                                                    Log.info(message: "key: \(item.key) value: \(item.value)")
                                                    if item.key == "error" {
                                                        fcm_error = true
                                                        fcm_er = item.value as? String ?? ""
                                                    }
                                                }
                                            }
                                        }
                                        if fcm_error {
                                            Log.info(message: "bodyJson is\(bodyJSON.isEmpty ? "" : "n't") empty")
                                            Log.info(message: "bodyJSON[\"results\"] is\(bodyJSON["results"] == nil ? "" : "n't") nil and bodyJSON[\"results\"] is\((bodyJSON["results"] as! [Any]).isEmpty ? "" : "n't") empty")
                                            errors.fcmCommunication(resp, phone: phone, request: req, log: "FCM error: \(fcm_er) phone: \(phone)")
                                            return
                                        }
                                        success(resp, message: "Message sent!")
                                    } catch let error as CURLResponse.Error {
                                        errors.internalServer(resp, phone: phone, request: req, log: "Failed: response code \(error.response.responseCode)")
                                        return
                                    } catch {
                                        errors.internalServer(resp, phone: phone, request: req, log: "Fatal error \(error)")
                                        return
                                    }
                                }
                            } else {
                                errors.wrongPassword(resp)
                                return
                            }
                        } else {
                            errors.internalServer(resp, phone: phone, request: req, log: "passInDB is nil")
                            return
                        }
                    } catch {
                        errors.passwordVerification(resp, phone: phone, request: req, log: "Bcrypt error: \(error) passGiven: \(pass)")
                        return
                    }
                    dataMysql.close()
                }
            }
        } else {
            errors.internalServer(resp, phone: phone, request: req, log: "results \(ress != nil ? "not" : "") nil and fields \(ress?.numRows)")
            return
        }
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
    }
}))

routes.add(Route(method: .post, uri: "/server/getloc", handler: { (req, resp) -> () in
    let request = req.postParams[0].1
    if let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var pass = ""
        var myphone = ""
        var test = false
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                phone = json["phone"] as? String ?? ""
                pass = json["pass"] as? String ?? ""
                myphone = json["myphone"] as? String ?? ""
                test = json["test"] as? Bool ?? false
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, phone: myphone, reqPhone: phone, request: req, log: "Failure connecting to data server \(Host)")
            return
        }
        var testAdd = ""
        if test {
            testAdd = "_test"
        }

        var ress: MySQLStmt.Results?

        let dataSql = dataMysql.secureQuery(statement: "SELECT * FROM location_users\(testAdd) WHERE phone = ?", params: [phone])

        if dataSql == nil {
            errors.dataServerConnection(resp, phone: myphone, reqPhone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }

        ress = dataSql?.results()

        if let results: MySQLStmt.Results = ress, results.numRows > 0 {
            results.forEachRow { item in
                if let passInDB = item[2] as? String, let lat = item[4], let long = item[5] {
                        do {
                            if try BCrypt.verify(password: pass, matchesHash: passInDB) {
                                let json = "{" +
                                        "\"lat\": \"\(lat)\"," +
                                        "\"long\": \"\(long)\"," +
                                        "\"result\": \"success\"," +
                                        "\"error\": false" +
                                        "}"
                                resp.setBody(string: json)
                                resp.completed()
                            } else {
                                errors.wrongPassword(resp)
                                return
                            }
                        } catch {
                            errors.passwordVerification(resp, phone: myphone, reqPhone: phone, request: req, log: "Bcrypt error: \(error) passGiven: \(pass)")
                            return
                        }
                } else {
                    errors.phoneRegistration(resp, phone: myphone, reqPhone: phone, request: req, log: "DBPassword nil or lat nil or long nil")
                    return
                }
                dataMysql.close()
                return
            }
        } else {
            errors.internalServer(resp, phone: myphone, reqPhone: phone, request: req, log: "results nil")
            return
        }
    } else {
        errors.processingData(resp,request: req, log: "Error nil request data")
    }
}))

routes.add(method: .get, uris: ["/server/errorlog/{phone}/{pass}/{id}", "/server/errorlog/{phone}/{pass}"], handler: { (req, resp) -> () in
    var phone = req.urlVariables["phone"] ?? ""
    var pass = req.urlVariables["pass"] ?? ""
    var id = req.urlVariables["id"] ?? ""

    if (phone != "admin" || pass != "12345678") {
        errors.wrongPassword(resp)
        return
    }
    let dataMysql = MySQL()
    if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
        errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure connecting to data server \(Host)")
        return
    }
    if id == "" {
        if !dataMysql.query(statement: "SELECT * FROM error_log_database ORDER BY `id` DESC") {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var json1 = "{" +
                "\"errors\":["

        let json2 = "{ \"Id\":0, \"Text\":\"END\", \"Description\":\"END!!!\" }" +
                "]," +
                "\"error\": false" +
                "}"
        if let results = dataMysql.storeResults() {
            while let item = results.next() {
                if let id = item[0], let text = item[1], let description = item[2] {
                    json1 += "{ \"Id\":\(id), \"Text\":\"\(text)\", \"Description\":\"\(description)\" },"
                }
            }
        }
        resp.setBody(string: json1 + json2)
        resp.completed()
    } else {
        var ress: MySQLStmt.Results?
        if dataMysql.secureQuery(statement: "DELETE FROM `error_log_database` WHERE `error_log_database`.`id` = ?", params: [id]) == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
        } else {
            success(resp)
        }
    }
})

routes.add(method: .post, uri: "/server/sendnotifications", handler: { (req, resp) -> () in
    if let dataFromString = req.postBodyString?.data(using: .utf8, allowLossyConversion: false) {
        var phone = ""
        var pass = ""
        var important = false
        var title = ""
        var desc = ""
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                phone = json["phone"] as? String ?? ""
                pass = json["pass"] as? String ?? ""
                title = json["title"] as? String ?? ""
                desc = json["desc"] as? String ?? ""
                important = json["important"] as? Bool ?? false
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        var topic = !important ? "news" : "important"
        if (phone != "admin" || pass != "12345678") {
            errors.wrongPassword(resp)
            return
        }

        Log.info(message: "topic: \(topic)")
        let message = "{" +
                "\"data\": {" +
                "\"title\": \"\(title)\"," +
                "\"body\": \"\(desc)\"," +
                "\"notification\": true" +
                "}," +
                "\"to\" : \"/topics/\(topic)\"" +
                "}"
        let url = "https://fcm.googleapis.com/fcm/send"
        CURLRequest.init(url, CURLRequest.Option.addHeader(.contentType, "application/json"), CURLRequest.Option.addHeader(.authorization, "key=AAAAXpJU92g:APA92bSwwiGPZ-CG2oC73dJa7dI139pIdk7ZpasGhnUJ2BC7Rcz2YgeyAnzfuHTX3Qiue-54m-tBs_owfwagPW1lGic3nmRvzLanjyEeMRI1JN1io-AZl-zkbUhbMAOTWYK3d9GFu9z5"), CURLRequest.Option.httpMethod(HTTPMethod.post), CURLRequest.Option.postString(message)).perform {
            confirmation in
            do {
                let response = try confirmation()
                if (response.responseCode != 200) {
                    errors.internalServer(resp, log: "Failed: response code \(response.responseCode)")
                    return
                }
                var fcm_error = false
                var fcm_er = ""
                let bodyJSON = response.bodyJSON
                if let res = bodyJSON["results"] as? [Any] {
                    for item1 in res {
                        if let item = (item1 as? [String: Any] ?? [:]).first {
                            Log.info(message: "key: \(item.key) value: \(item.value)")
                            if item.key == "error" {
                                fcm_error = true
                                fcm_er = item.value as? String ?? ""
                            }
                        }
                    }
                }
                if fcm_error {
                    Log.info(message: "bodyJson is\(bodyJSON.isEmpty ? "" : "n't") empty")
                    Log.info(message: "bodyJSON[\"results\"] is\(bodyJSON["results"] == nil ? "" : "n't") nil and bodyJSON[\"results\"] is\((bodyJSON["results"] as! [Any]).isEmpty ? "" : "n't") empty")
                    errors.fcmCommunication(resp, phone: phone, request: req, log: "FCM error: \(fcm_er) phone: \(phone)")
                    return
                }
                success(resp, message: "Message sent!")
            } catch let error as CURLResponse.Error {
                errors.internalServer(resp, phone: phone, request: req, log: "Failed: response code \(error.response.responseCode)")
                return
            } catch {
                errors.internalServer(resp, phone: phone, request: req, log: "Fatal error \(error)")
                return
            }
        }
    }
})

routes.add(method: .post, uri: "/server/support") {
    req, resp in
    if let request = req.postBodyString, let dataFromString = request.data(using: .utf8, allowLossyConversion: false) {
        var name = ""
        var mail = ""
        var message = ""
        do {
            if let json = try JSONSerialization.jsonObject(with: dataFromString) as? [String: Any] {
                name = json["name"] as? String ?? ""
                mail = json["mail"] as? String ?? ""
                message = json["message"] as? String ?? ""
            } else {
                errors.processingData(resp, request: req, log: "Error deserializing JSON, nil json")
                return
            }
        } catch {
            errors.processingData(resp, request: req, log: "Error deserializing JSON: \(error)")
            return
        }
        let dataMysql = MySQL()
        if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
            errors.dataServerConnection(resp, request: req, log: "Failure connecting to data server \(Host)")
            return
        }
        let mySQL = MySQLStmt(dataMysql)
        mySQL.reset()
        if !mySQL.prepare(statement: "INSERT INTO `support_database` (`id`, `name`, `mail`, `message`) VALUES (NULL, ?, ?, ?)") {
            errors.dataServerConnection(resp, request: req, log: "Failure preparing query: 'INSERT INTO `support_database` (`id`, `name`, `mail`, `message`) VALUES (NULL, ?, ?, ?)'")
            return
        }
        mySQL.bindParam(name)
        mySQL.bindParam(mail)
        mySQL.bindParam(message)
        if !mySQL.execute() {
            errors.dataServerConnection(resp, request: req, log: "Failure executing query: 'INSERT INTO `support_database` (`id`, `name`, `mail`, `message`) VALUES (NULL, ?, ?, ?)'")
            return
        }
        errors.sendNotificationToAdmin(title: "Support", body: "From \(name)", error: false)
        mySQL.close()
        dataMysql.close()
        success(resp)
    } else {
        errors.processingData(resp, request: req, log: "Error nil request data")
        return
    }
}

routes.add(method: .get, uris: ["/server/supportlog/{phone}/{pass}/{id}", "/server/supportlog/{phone}/{pass}"], handler: { (req, resp) -> () in
    var phone = req.urlVariables["phone"] ?? ""
    var pass = req.urlVariables["pass"] ?? ""
    var id = req.urlVariables["id"] ?? ""

    if (phone != "admin" || pass != "12345678") {
        errors.wrongPassword(resp)
        return
    }
    let dataMysql = MySQL()
    if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
        errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure connecting to data server \(Host)")
        return
    }
    if id == "" {
        if !dataMysql.query(statement: "SELECT * FROM support_database ORDER BY `id` DESC") {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
            return
        }
        var json1 = "{" +
                "\"errors\":["

        let json2 = "{ \"Id\":0, \"Text\":\"END\", \"Description\":\"END!!!\" }" +
                "]," +
                "\"error\": false" +
                "}"
        if let results = dataMysql.storeResults() {
            while let item = results.next() {
                if let id = item[0], let name = item[1], let mail = item[2], let msg = item[3] {
                    json1 += "{ \"Id\":\(id.stringByReplacing(string: "\"", withString: "\\\"")), \"Text\":\"From \(name.stringByReplacing(string: "\"", withString: "\\\""))\", \"Description\":\"\(msg)\n\nE-Mail for contact: \(mail.stringByReplacing(string: "\"", withString: "\\\""))\" },"
                }
            }
        }
        resp.setBody(string: json1 + json2)
        resp.completed()
    } else {
        var ress: MySQLStmt.Results?
        if dataMysql.secureQuery(statement: "DELETE FROM `support_database` WHERE `support_database`.`id` = ?", params: [id]) == nil {
            errors.dataServerConnection(resp, phone: phone, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
        } else {
            success(resp)
        }
    }
})

routes.add(method: .get, uris: ["/server/report/{which}", "/server/report"], handler: {
    req, resp in
    var which = req.urlVariables["which"] ?? ""
    if which != "" && which != "0" {
        which = ".1"
    } else {
        which = ""
    }
    let thisFile = File("/home/server/report.html")
    if thisFile.exists {
        thisFile.delete()
    }
    if executeShell(command: "/usr/bin/goaccess", arguments: ["/var/log/apache2/other_vhosts_access.log\(which)", "-a", "-o", "/home/server/report.html"]) != nil {
        if let string = try? thisFile.readString() {
            resp.appendBody(string: string)
            resp.completed()
        } else {
            errors.internalServer(resp, phone: nil, reqPhone: nil, request: req, log: "Goaccess report file can't be read.")
        }
    } else {
        errors.internalServer(resp, phone: nil, reqPhone: nil, request: req, log: "Goaccess execution result is nil.")
    }
})

routes.add(method: .get, uri: "/server/webcam/{phone}/{pass}", handler: {
    req, resp in
    var phone = req.urlVariables["phone"] ?? ""
    var pass = req.urlVariables["pass"] ?? ""
    if (phone != "admin" || pass != "12345678") {
        errors.wrongPassword(resp)
        return
    }

    let thisFile = File("/home/server/webcam.jpg")
    if thisFile.exists {
        thisFile.delete()
    }
    //-r 1280x720 --jpeg 100 -D 3 -S 13 /home/server/webcam.jpg
    if executeShell(command: "/usr/bin/fswebcam", arguments: ["-r", "1280x720", "--jpeg", "100", "-D", "3", "-S", "13", "/home/server/webcam.jpg"]) != nil {
        if let body = try? thisFile.readSomeBytes(count: thisFile.size) {
            resp.appendBody(bytes: body)
            resp.completed()
        } else {
            errors.internalServer(resp, phone: nil, reqPhone: nil, request: req, log: "WebCamera picture can't be read.")
        }
    } else {
        errors.internalServer(resp, phone: nil, reqPhone: nil, request: req, log: "Fswebcam execution result is nil.")
    }
})

routes.add(method: .post, uri: "/server/betatesters", handler: {
    req, resp in

    resp.addHeader(.accessControlAllowOrigin, value: "http://192.168.100.99:63354")

    let dataMysql = MySQL()
    if !dataMysql.connect(host: Host, user: User, password: Password, db: Database) {
        errors.dataServerConnection(resp, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
        return
    }


    dataMysql.query(statement: "SELECT * FROM location_users_test")

    if let ress: MySQL.Results = dataMysql.storeResults() {
        success(resp, message: String(ress.numRows()))
    } else {
        errors.dataServerConnection(resp, request: req, log: "Failure: \(dataMysql.errorCode()) \(dataMysql.errorMessage())")
        return
    }
})

let server = FastCGIServer()
server.addRoutes(routes)

do {
    // Launch the FastCGI server
    // The path to the sock file must point to a directory one level up from the site's document root.
    // The file must be called "perfect.fastcgi.sock"
    // For example, the following path would suffice for a server whose document root is:
    // /Library/WebServer/VirtualHosts/wwwroot/
    try server.start(namedPipe: "/home/server/perfectServer/webroot/perfect.fastcgi.sock")
} catch {
    print("Error thrown: \(error)")
}
