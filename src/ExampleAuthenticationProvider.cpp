///////////////////////////////////////////////////////////////////////////////
//
//  Copyright PHOENIX CONTACT Electronics GmbH
//
///////////////////////////////////////////////////////////////////////////////
#include "Arp/System/Um/Commons/UmAuthenticationResult.hpp"
#include "ExampleAuthenticationProvider.hpp"
#include "UmModuleEx.hpp"
#include "UmModuleExConfig.hpp"
#include "otacverify.h"
#include "jwt/jwt.hpp"

namespace Arp { namespace System { namespace UmModuleEx
{

ExampleAuthenticationProvider::ExampleAuthenticationProvider(UmModuleEx& mod)
    : mod(mod)
{
    using namespace jwt::params;
    const std::string pub_key_path = "/opt/plcnext/test/public/test.key";
    const std::string token_path = "/opt/plcnext/test/testLicense";
    auto pub_key = read_from_file(pub_key_path);
    auto token = read_from_file(token_path); //license file
    jwt::jwt_object dec_obj;
    std::string hostId;
    String payload;
    std::vector<String> v;
    
    try {
        dec_obj = jwt::decode(token, algorithms({"RS256"}), verify(true), secret(pub_key));
    }
    catch (const std::exception& e) {
        log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
        mod.licenseCheckFail();
    }

    try{
        hostId = exec("hostid"); //OS hostID
    }
    catch(const std::exception& e){
        log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
        mod.licenseCheckFail();
    }

    if (dec_obj.has_claim("hostId")) {
        try{
            payload = dec_obj.payload().get_claim_value<std::string>("hostId"); //payload hostID
            int flag = 0;
            if (payload.Find('|') != -1){
                v = payload.Split('|');
                for (int i = 0 ; i < v.size() ; i ++){
                    //log.Debug("ExampleAuthenticationProvider: payload hostid={0}", v[i]);
                    if(!v[i].Compare(hostId)){
                        log.Debug("ExampleAuthenticationProvider: License Check SUCCESS");
                        flag = 1;
                        break;
                    }
                }
                if (flag != 1) {
                    log.Debug("ExampleAuthenticationProvider: HostID compare failed");
                    mod.licenseCheckFail();
                }
            }
            else{
                if (!payload.Compare(hostId)) {
                    log.Debug("ExampleAuthenticationProvider: License Check SUCCESS");
                }
                else {
                    log.Debug("ExampleAuthenticationProvider: HostID compare failed");
                    mod.licenseCheckFail();
                }
            }
        }
        catch(const exception& e){
            log.Debug("ExampleAuthenticationProvider: Error occurred={0}", e.what());
            mod.licenseCheckFail();
        }
    }
    else {
        log.Debug("ExampleAuthenticationProvider: HasClaim=false");
        mod.licenseCheckFail();
    }

    vector<String>().swap(v);
}

UmAuthenticationResult ExampleAuthenticationProvider::AuthenticateUser(const String& username,
        const String& password, SessionInfo& sessionInfo)
{
    if (!mod.Started())
    {
        return UmAuthenticationResult::Failed;
    }
    if (!mod.UserauthStarted())
    {   
        log.Debug("ExampleAuthenticationProvider: License Check Failed");
        return UmAuthenticationResult::Failed;
    }
     
    log.Debug("ExampleAuthenticationProvider: UserAuthStarted={0}", mod.UserauthStarted());//start log
    
    const UserConfTag& userconf = mod.GetConfig()->userConf;

    OtacVerify handler(password.CStr());

    handler.Otac_Set_Host_IP();

    handler.Otac_Set_Post(userconf.url.CStr());

    handler.Otac_Request();
    
    Json::Value root = handler.Otac_Get_Root();

     if (root["userId"] == username.CStr())
     {
          if (root["result"] == "SUCCESS")
         {  
             String Role(root["userRoles"].asCString());
             std::list<String> roles;

             if (Role.Find('|') != -1){
                std::vector<String> v = Role.Split('|');
                for (int i = 0 ; i < v.size() ; i ++){
                    roles.push_back(v[i]);
                }
                sessionInfo.SetRoles(roles);
                return UmAuthenticationResult::Success;
             }
             roles = {Role};
             sessionInfo.SetRoles(roles);            
             return UmAuthenticationResult::Success;
         }
         else
         {   
             return UmAuthenticationResult::WrongPassword;
         }
    }
    return UmAuthenticationResult::Failed;    

}

void ExampleAuthenticationProvider::OnSessionClose(SessionInfo& session)
{
    String clientIpAdress;
    String accessToken;
    log.Debug("ExampleAuthenticationProvider: session closed, id={0}, session holding lock={1}, clientIp={2}, accessToken={3}, protocolObjName={4}, user={5}",
             session.GetSecurityToken(), mod.GetLockedSession(), clientIpAdress, accessToken, session.GetProtocolObjName(), session.GetUserName());

    mod.UnlockSession(session);
}


std::string ExampleAuthenticationProvider::exec(const char* cmd)
{
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        log.Debug("ExampleAuthenticationProvider: excute cmd failed!(pipe)");
    }

    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
              buffer[len - 1] = '\0';
            }
            result += buffer;  
        }
    } catch (...) {
        log.Debug("ExampleAuthenticationProvider: excute cmd failed!(fgets)");
        pclose(pipe);
    }

    pclose(pipe);
    return result;
}

std::string ExampleAuthenticationProvider::read_from_file(const std::string& path)
{
  std::string contents;
  std::ifstream is{path, std::ifstream::binary};

  if (is) {
    // get length of file:
    is.seekg (0, is.end);
    auto length = is.tellg();
    is.seekg (0, is.beg);
    contents.resize(length);

    is.read(&contents[0], length);
    if (!is) {
      is.close();
      return {};
    }
  } else {
    log.Debug("ExampleAuthenticationProvider: FILE not FOUND!!");
  }

  is.close();
  return contents;
}

}}} // end of namespace Arp::System::UmModuleEx




