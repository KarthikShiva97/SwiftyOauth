import UIKit
import PlaygroundSupport


public enum OauthErrors:Error{
    case AccessTokenMissing
    case RefreshTokenMissing
    case InvalidAuthCode
}


class NetworkRequest {

    private var httpBody = Data()
    private var httpRequestType = String()
    private var baseURL:URL = URL(string: "https://www.zohoapis.com/crm/v2")!
    private var addZohoOauthHeader:Bool = false
    private var HTTPRequestHeaders = [String:String]()
    private var authTokenManager:AuthTokenManager?

    public enum HttpRequestType:String {
        case GET,POST,PUT,DELETE,NONE
    }

    private enum NetworkRequestErrors:Error{
        case InvalidHttpRequestType(String)
    }

    private enum NetworkingErrors:Error{
        case InvalidURL
        case EmptyHTTPBody
        case EmptyHTTPHeader

    }
    /// Empty Init for requests which dont require Authorization
    init(){
    }
    /// Pass in an Instance of AuthTokenManager to authorize your requests
    init(authTokenManager:AuthTokenManager) {
        self.authTokenManager = authTokenManager
    }

}

extension NetworkRequest {

    func setBaseURL(url:String) throws {
        guard let url = URL(string: url) else {throw NetworkingErrors.InvalidURL}
        self.baseURL = url
    }

    func appendURLPath(Component:String) {
        self.baseURL.appendPathComponent(Component)
    }

    func setDataForRequest(data:Data)throws{
        guard !data.isEmpty else {throw NetworkingErrors.EmptyHTTPBody}
        self.httpBody = data
    }

    func setHttpRequest(Type:HttpRequestType) throws {

        typealias reqType  = HttpRequestType

        switch Type {
        case .POST:
            self.httpRequestType = reqType.POST.rawValue
        case .GET:
            self.httpRequestType = reqType.GET.rawValue
        case .PUT:
            self.httpRequestType = reqType.PUT.rawValue
        case .DELETE:
            self.httpRequestType = reqType.DELETE.rawValue
        case .NONE:
            throw NetworkRequestErrors.InvalidHttpRequestType("NONE is used only as an initial value !")
        }
    }

    func setZohoOauthTokenHeader() throws {
        guard ((authTokenManager?.accessToken.isEmpty) == false) else { throw OauthErrors.AccessTokenMissing }
        addZohoOauthHeader = true
    }

    func addURLRequestParameters(params:[String:String]) {

        var baseURLString = self.baseURL.absoluteString
        baseURLString.append("?")
        for (key,value) in params {
            baseURLString += "\(key)=\(value)&"
        }
        baseURLString = String(baseURLString.dropLast())
        do{try setBaseURL(url: baseURLString)}
        catch let error{print(error)}
    }


    func addHTTPRequestHeaders(headers:[String:String]) throws {

        for (header,value) in headers {

            guard !header.isEmpty && !value.isEmpty else {throw NetworkingErrors.EmptyHTTPHeader}
        }
        self.HTTPRequestHeaders = headers
    }


    func makeNetworkRequest(handler: @escaping (_ Data:Data?,_ Response:URLResponse?,_ Error:Error?)->() ){

        var request = URLRequest(url: self.baseURL)
        request.httpMethod = httpRequestType

        if addZohoOauthHeader == true {
            if let authTokenManager = authTokenManager {
            request.addValue("Zoho-oauthtoken " + authTokenManager.accessToken , forHTTPHeaderField: "Authorization")
            }
        }
        
        if HTTPRequestHeaders.isEmpty == false {
            for (header,value) in HTTPRequestHeaders {
                request.addValue(value, forHTTPHeaderField: header)
            }
        }
        
        URLSession.shared.dataTask(with: request) { (data, response, error) in
            handler(data, response, error)
            }.resume()

       }

} // extension ends


extension NetworkRequest { // getters

    func getBaseURL()-> URL{
        return baseURL
    }

}



class AuthTokenManager {

    private let timer = DispatchSource.makeTimerSource()
    private var timerState:TimerState = .Suspended
    private var accessTokenUpdateInterval = DispatchTimeInterval.seconds(3600)
    private var timerLeeway = DispatchTimeInterval.nanoseconds(30) // Timer Sleep Period
    private var clientID = String()
    private var clientSecret = String()
    private var redirectURI = String()
    private var authCode = String()
    private var accessTokenURL:String = "https://accounts.zoho.com/oauth/v2/token"
    private var networkRequest = NetworkRequest()
    public  var accessToken = String()
    public  var tokens = Tokens()
    public  static var dispatchGroup = DispatchGroup()


    private enum TimerState {
        case Suspended
        case Resumed
    }

    init(){

    }

    init(clientID:String,clientSecret:String,redirectURI:String,authCode:String,accessTokenExpiry:UInt?) {
        guard validateOauth(Inputs: clientID,clientSecret,redirectURI,authCode) else {return}
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.authCode = authCode
        self.redirectURI = redirectURI
        if let accessTokenExpiry = accessTokenExpiry {
            if accessTokenExpiry > 300 { // min access token expiry = 5 mins
           let accessTokenUpdateInterval =  Int(accessTokenExpiry) - 180 // updates 3 mins before token expiryTime
           let leeway =  ( (accessTokenUpdateInterval * 30) / 5 )
           self.timerLeeway = DispatchTimeInterval.nanoseconds(leeway) // timer sleep period
           self.accessTokenUpdateInterval = DispatchTimeInterval.seconds(accessTokenUpdateInterval)
            }
        }
        getAccessAndRefreshTokens()
    }
}


extension AuthTokenManager {
    struct Tokens: Codable {
        var accessToken:String?
        var refreshToken:String?
        var expiresIn:Int?
        var tokenType:String?


    public enum CodingKeys : String,CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }
    }
}


extension AuthTokenManager {


    func switchTimerState(){
        if self.timerState == .Resumed {
            self.timer.suspend()
            self.timerState = .Suspended
        } else {
            self.timer.resume()
            self.timerState = .Resumed
        }
    }


    private func validateOauth(Inputs:String...)-> Bool{
        for ip in Inputs {
            if ip.isEmpty || ip.count < 5 {return false}
        }
        return true
    }


    private func getAccessAndRefreshTokens(){
       let tokenRequestBody = ["grant_type":"authorization_code","client_id":clientID,"client_secret":clientSecret,"redirect_uri":redirectURI,"code":authCode]

        do{
        try networkRequest.setBaseURL(url: accessTokenURL)
            networkRequest.addURLRequestParameters(params: tokenRequestBody)
        try networkRequest.setHttpRequest(Type: .POST)
        }   catch let error {
            print(error)
        }
       AuthTokenManager.dispatchGroup.enter()
       networkRequest.makeNetworkRequest { (data, response, error) in

            guard error == nil else {return}
            guard let data = data else {return}
            do{
            let decodedTokens = try JSONDecoder().decode(Tokens.self, from: data)
            guard decodedTokens.accessToken != nil && decodedTokens.refreshToken != nil else{
                print("Invalid Auth Code")
                return
                }
            self.tokens = decodedTokens
            self.accessToken = self.tokens.accessToken!
            } catch let error {
                print(error)
            }
        
            self.updateAccessTokenPeriodically()
        }
    }


    private func updateAccessTokenPeriodically(){
        print("Current Token",self.accessToken)
        timer.schedule(deadline: .now() , repeating: accessTokenUpdateInterval, leeway: .seconds(0))
        timer.setEventHandler {
        self.getNewAccessToken()
        } //timer
        switchTimerState()
    }


private func getNewAccessToken(){
    let tokenRequestBody = ["grant_type":"refresh_token","client_id":self.clientID,"client_secret":self.clientSecret,"refresh_token":self.tokens.refreshToken!]
    do {
        try self.networkRequest.setBaseURL(url: self.accessTokenURL)
        self.networkRequest.addURLRequestParameters(params: tokenRequestBody)
        try self.networkRequest.setHttpRequest(Type: .POST)
       } catch let error {
        print(error)
    }

    self.networkRequest.makeNetworkRequest{ (data, response, error) in
        guard error == nil else {return}
        guard let data = data else {return}
        do{
            let decodedAccessToken = try JSONDecoder().decode(Tokens.self, from: data)
            self.tokens.accessToken = decodedAccessToken.accessToken
            self.accessToken = self.tokens.accessToken!
            print("New Access Token",self.accessToken)
         } catch let error {
            print(error)
         }
        AuthTokenManager.dispatchGroup.leave()
     }
 }
}// extension ends


class Disk {
    static func store<T:Codable>(Object:T,withFileName:String)->Bool {
        
        let filePath = getDocumentsDirectory().appendingPathComponent(withFileName)
        do
        {
            let fileData = try JSONEncoder().encode(Object)
            try fileData.write(to: filePath)
            return true
        } catch let error {
            print(error)
            return false
        }
    }
    
    static func getObjectFrom<T:Codable>(FileName:String,withType:T)->T? {
        
       let filePath = getDocumentsDirectory().appendingPathComponent(FileName)
       do
       {
       let fileData = try Data(contentsOf: filePath)
       let object = try JSONDecoder().decode(T.self, from: fileData)
       return object
       } catch let error {
       print(error)
       return nil
       }
    }
    
    private static func getDocumentsDirectory() -> URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        return paths[0]
    }
    
}




struct ZCRMRecord:Decodable {
    var id : String?
    var fieldNameVsValue:[String:Any?] = [String:Any?]() //left out
    var properties:[String:Any?] = [ String : Any? ]() //left out
    var lineItems:[ZCRMInventoryLineItem]?
    var tax :[ZCRMTax]?
    var owner : ZCRMUser?
    var createdBy : ZCRMUser?
    var modifiedBy : ZCRMUser?
    var createdTime : String?
    var modifiedTime : String?
    public static let standardFields = ["id","Product_Details","$line_tax","Owner","Created_By","Modified_By","Created_Time","Modified_Time"]

    enum CodingKeys:String,CodingKey{
        case id = "id"
        case lineItems = "Product_Details"
        case tax = "$line_tax"
        case owner = "Owner"
        case createdBy = "Created_By"
        case modifiedBy = "Modified_By"
        case createdTime = "Created_Time"
        case modifiedTime = "Modified_Time"
    }

}

//extension ZCRMRecord : Decodable {
//
//    init(from decoder:Decoder) throws {
//
//        let container = try decoder.container(keyedBy: CodingKeys.self)
//        let data = try container.nestedContainer(keyedBy: CodingKeys.self, forKey: .data)
//        id = try data.decodeIfPresent(Int64.self, forKey: .id)
//        lineItems = try data.decodeIfPresent([ZCRMInventoryLineItem].self, forKey: .lineItems)
//        tax = try data.decodeIfPresent([ZCRMTax].self, forKey: .tax)
//        owner = try data.decode(ZCRMUser.self, forKey: .owner)
//        createdBy = try data.decode(ZCRMUser.self, forKey: .createdBy)
//        modifiedBy = try data.decode(ZCRMUser.self, forKey: .modifiedBy)
//        createdTime = try data.decodeIfPresent(String.self, forKey: .createdTime)
//        modifiedTime = try data.decodeIfPresent(String.self, forKey: .modifiedTime)
//
//    }
//
//}


struct ZCRMUser : Codable
{
    private var id :String?
    private var name: String?
}

struct ZCRMInventoryLineItem : Codable
{
    private var product : Product
    private var id : String?
    private var listPrice : Double = 0.0
    private var quantity : Double = 1.0
    private var description : String?
    private var total : Double = 0.0
    private var discount : Double = 0.0
    private var discountPercentage : Double = 0.0
    private var totalAfterDiscount : Double = 0.0
    private var tax : Double = 0.0
    private var lineTaxes : [ZCRMTax]?
    private var netTotal : Double = 0.0
    private var deleteFlag : Bool = false

    enum CodingKeys:String,CodingKey {
        case id
        case product
        case listPrice = "list_price"
        case quantity
        case description = "product_description"
        case total
        case discount = "Discount"
        case totalAfterDiscount = "total_after_discount"
        case tax = "Tax"
        case lineTaxes = "$line_tax"
        case netTotal = "net_total"
    }
}

struct Product : Codable {

    private var productName:String?
    private var productCode:String?
    private var productId:String?

    enum CodingKeys:String,CodingKey {
        case productCode =  "Product_Code"
        case productName = "name"
        case productId = "id"
    }
}

struct ZCRMTax: Codable
{
    private var taxName : String?
    private var percentage : Double?
    private var value : Double?

    enum CodingKeys:String,CodingKey{
        case percentage
        case taxName = "name"
        case value
    }
}


struct Root:Decodable {
    var data = [ZCRMRecord]()
    
}





let authTokenManager = AuthTokenManager(clientID: "1000.S90TSTPVX9PR38403656RQHGE70Y2N", clientSecret: "7db3c01ec1801665831eaa43edd1f90bd983629ffa", redirectURI: "https://www.test.com", authCode: "1000.444326e50060f07ff81ec5c81886fbb5.a1a54ca87bf3dd95ef28b6fba9d17799", accessTokenExpiry: 3600)


var dataStruct = Root()

AuthTokenManager.dispatchGroup.notify(queue: .main) {

let req = NetworkRequest(authTokenManager: authTokenManager)
do {
try req.setBaseURL(url: "https://www.zohoapis.com/crm/v2")
try req.setHttpRequest(Type: .GET)
    req.appendURLPath(Component: "Purchase_Orders")
    try req.setZohoOauthTokenHeader()
    req.makeNetworkRequest { (data, response, error) in
        guard error == nil else {return}
        guard let data = data else {return}
        
        //print(String(data: data, encoding: .utf8))
   do{
    

    
    dataStruct = try JSONDecoder().decode(Root.self, from: data)
    guard let jsonObj = try? JSONSerialization.jsonObject(with: data, options: []) else {return}
    guard let dict = jsonObj  as? [String:Any] else {return}
    guard let jsonDict = dict["data"] as? [[String:Any]] else {return}

        for i in (0..<jsonDict.count){

            for (key,value) in jsonDict[i] {
             
                if key.hasPrefix("$"){
                    dataStruct.data[i].properties[key] = value
                }
                
                if ZCRMRecord.standardFields.contains(key) == false && key.hasPrefix("$") == false {
                    dataStruct.data[i].fieldNameVsValue[key] = value
                }
                
            }
        }
    
    for record in dataStruct.data{
        
        print("\(record.lineItems![0]) \n ******************** END OF RECORD ********************\n")
    }
    
    } catch let error {
      print(error)
      } //try ends
    
   } // network req
    
    
} catch let error {
    print("ERROR \(error)")
}

} // Dispatch ends







//{
//    "data": [
//    {
//    "Owner": {
//    "name": "Karthik Shiva",
//    "id": "2931549000000136011"
//    },
//    "Email": "gg@gmail.com",
//    "$currency_symbol": "XCD",
//    "Visitor_Score": null,
//    "Other_Phone": null,
//    "Mailing_State": null,
//    "Other_State": null,
//    "Other_Country": null,
//    "Last_Activity_Time": "2018-06-11T14:56:29+05:30",
//    "Department": null,
//    "$process_flow": false,
//    "Assistant": null,
//    "Mailing_Country": null,
//    "id": "2931549000000270017",
//    "$approved": true,
//    "$approval": {
//    "delegate": false,
//    "approve": false,
//    "reject": false,
//    "resubmit": false
//    },
//    "First_Visited_URL": null,
//    "Days_Visited": null,
//    "Other_City": null,
//    "Created_Time": "2018-06-11T14:45:08+05:30",
//    "$followed": false,
//    "$editable": true,
//    "Home_Phone": null,
//    "Last_Visited_Time": null,
//    "Created_By": {
//    "name": "Karthik Shiva",
//    "id": "2931549000000136011"
//    },
//    "Secondary_Email": null,
//    "Description": null,
//    "Vendor_Name": null,
//    "Mailing_Zip": null,
//    "Reports_To": null,
//    "Number_Of_Chats": null,
//    "Twitter": null,
//    "Other_Zip": null,
//    "Mailing_Street": null,
//    "Average_Time_Spent_Minutes": null,
//    "Salutation": null,
//    "First_Name": null,
//    "Full_Name": "Rajesh",
//    "Asst_Phone": null,
//    "Modified_By": {
//    "name": "Karthik Shiva",
//    "id": "2931549000000136011"
//    },
//    "Skype_ID": null,
//    "Phone": null,
//    "Account_Name": null,
//    "Email_Opt_Out": false,
//    "Modified_Time": "2018-06-11T14:45:08+05:30",
//    "Date_of_Birth": null,
//    "Mailing_City": null,
//    "Title": null,
//    "Other_Street": null,
//    "Mobile": null,
//    "First_Visited_Time": null,
//    "Last_Name": "Rajesh",
//    "Referrer": null,
//    "Lead_Source": null,
//    "Tag": [],
//    "Fax": null
//    } ]
//
//}
//
//
