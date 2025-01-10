"""This script saves the worlds of your friends as well as your own.

Upon activation, the script will ask you for your email address (the email
address associated with your EA Origin account). A moment or so later, you will
receive an email with your verification code. Enter the code when prompted by
the script. After this the script will then download your town and your current
currency state. Then the script will download the towns of any friend associated
with your account.

The authentication component is from @damar1st. I greatly appreciate him
allowing me to use his code for this project.

@tjac.
"""

import base64
import binascii
import datetime
import json
import logging
import hashlib
import hmac
import os
import uuid

# pip install pycryptodome
from Crypto.Cipher import AES

# pip install requests
import requests

# The Simpsons: Tapped Out protobuffers
import AuthData_pb2
import GetFriendData_pb2
import LandData_pb2
import PurchaseData_pb2
import WholeLandTokenData_pb2

# Disable InsecureRequestWarning warnings.
import urllib3
urllib3.disable_warnings()

URL_SIMPSONS = 'prod.simpsons-ea.com'
URL_OFRIENDS = 'm.friends.dm.origin.com'
URL_AVATAR = 'm.avatar.dm.origin.com'
URL_TNTAUTH = 'auth.tnt-ea.com'
URL_TNTNUCLEUS = 'nucleus.tnt-ea.com'
URL_ACCOUNTS_EA = 'accounts.ea.com'
URL_GATEWAY_EA = 'gateway.ea.com'
CT_URLENCODED = 'application/x-www-form-urlencoded'
CT_PROTOBUF = 'application/x-protobuf'
CT_JSON = 'application/json'
CT_XML = 'application/xml'

VERSION_APP = '4.69.5'
VERSION_LAND = '72'

SECRET_KEY = '2Tok8RykmQD41uWDv5mI7JTZ7NIhcZAIPtiBm4Z5'   # found in libscorpio.so
CLIENT_ID = 'simpsons4-android-client'
CLIENT_SECRET = 'D0fpQvaBKmAgBRCwGPvROmBf96zHnAuZmNepQht44SgyhbCdCfFgtUTdCezpWpbRI8N6oPtb38aOVg2y'
HDRS = {'Accept': '/', 'Accept-Encoding': 'gzip', 'Connection': None, 'User-Agent': None}


# pull the current mayhem code and hash from damar1st's server
response = requests.get("https://damarist.de/mhcrc.txt")
data = response.text
datas = data.split(" ")
MHCODE = datas[0]
MHHASH = bytes(datas[1],  'utf-8')


class TSTO:
    def __init__(self):
        self.mLandMessage = LandData_pb2.LandMessage()
        self.mLandMessageExtra = None
        self.headers = dict()
        self.headers["Accept"] = "*/*"
        self.headers["Accept-Encoding"] = "gzip"
        self.headers["client_version"] = VERSION_APP
        self.headers["server_api_version"] = "4.0.0"
        self.headers["EA-SELL-ID"] = "857120"
        self.headers["platform"] = "android"
        self.headers["os_version"] = "4.4.4"
        self.headers["hw_model_id"] = "0 0.0"
        self.headers["data_param_1"] = "1495502718"
        self.mMhClientVersion = "Android." + VERSION_APP
        self.mSesSimpsons = requests.Session()
        self.mSesOther = requests.Session()
        self.mUid = None
        self.mSession = ''
        self.mEmail = ''
        self.mPasswd = ''

        # REQUEST CODE
        nonce = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S:000')
        anon_as = str(uuid.uuid4())
        ap = 'ewogICAiYXMiIDogIkExIiwKICAgImF2IiA6ICJ2MSIsCiAgICJzdiIgOiAidjEiLAogICAidHMiIDogIkEyIgp9Cg=='
        app = base64.b64decode(ap)
        app = app.decode('ascii')

        app = app.replace('A1', anon_as)
        app = app.replace('A2', nonce)
        si = app.encode()
        si = base64.b64encode(si)
        si = si.decode()
        si = si.replace('+', '-')
        si = si.replace('/', '_')
        si = si.replace('=', '')
        si = si.replace('\n', '')
        si = si.encode()

        si = si + '.'.encode('ascii') + base64.b64encode(
            binascii.unhexlify(hmac.new(SECRET_KEY.encode(), si, hashlib.sha256).hexdigest()))

        si = si.decode('ascii')
        si = si.replace('+', '-')
        si = si.replace('/', '_')
        si = si.replace('=', '')
        si = si.replace('\n', '')

        urget = "https://accounts.ea.com/connect/auth?authenticator_login_type=mobile_anonymous&client_id=simpsons4-android-client&redirect_uri=nucleus:rest&release_type=prod&response_type=code&sig=" + si
        data = requests.get(urget, headers=HDRS)
        jsonResponse = data.json()
        code = jsonResponse["code"]


        # Request ACCESS TOKEN
        h = HDRS.copy()
        h['X-Include-RT-Time'] = 'true'
        h['Content-Type'] = CT_URLENCODED
        urget2 = "https://accounts.ea.com/connect/token?client_id=simpsons4-android-client&client_secret="
        urget22 = "&code="
        urget222 = "&grant_type=authorization_code&redirect_uri=nucleus%3Arest&release_type=prod"
        data2 = requests.post(urget2 + CLIENT_SECRET + urget22 + code + urget222, headers=h)
        if data2.status_code != 200:
          print("Error getting initial token")
          exit(-1)

        jsonResponse2 = data2.json()
        acto = jsonResponse2["access_token"]
        reto = jsonResponse2["refresh_token"]
        idto = jsonResponse2["id_token"]

        # Initiate verification code
        """Initiate an authentication sequence by requesting a verification code."""
        url = "https://gateway.ea.com/proxy/identity/progreg/code"
        headers = {
          "Authorization": f"Bearer {acto}",
          "X-SEND-CODE": "true",
          "Content-Type": "text/plain;charset=UTF-8"
        }


        self.mEmail = input("Please enter your account email: ")
        body = json.dumps(
          {
            "codeType" : "EMAIL",
            "email" : self.mEmail
          }
        )

        req = requests.post(url, headers = headers, data = body)
        if req.status_code != 200:
          self.error(f"Unable to get verification code: {req.status_code}")
          self.error(req.text)
          exit(0)
        
        self.mPasswd = input("Please enter your verification code: ")

        # REQUEST AUTH - PID
        h = HDRS.copy()
        h['X-Check-Underage'] = 'true'
        h['X-Include-Authenticators'] = 'true'
        h['X-Include-StopProcess'] = 'true'

        urget3 = "https://accounts.ea.com/connect/tokeninfo?access_token=" + acto
        data3 = requests.get(urget3, headers=h)
        if data3.status_code != 200:
          print("Error getting initial tokeninfo")
          exit(-1)


        jsonResponse3 = data3.json()
        aupid = jsonResponse3["user_id"]


        # Request LONGLIVETOKEN
        tbase = "ewogICAiYXYiIDogInYxIiwKICAgImNyZWQiIDogIkRhbUF1dGgiLAogICAiZW1haWwiIDogIkRhbUVtYWlsIiwKICAgIm0iIDogIjEiLAogICAic3YiIDogInYxIiwKICAgInRzIiA6ICJEYW1Ob25jZSIKfQ=="
        tapp = base64.b64decode(tbase)
        tapp = tapp.decode('ascii')
        tapp = tapp.replace('DamEmail', self.mEmail)
        tapp = tapp.replace('DamAuth', self.mPasswd)
        tapp = tapp.replace('DamNonce', nonce)
        #print(tapp)

        tsi = tapp.encode()
        tsi = base64.b64encode(tsi)
        tsi = tsi.decode()
        tsi = tsi.replace('+', '-')
        tsi = tsi.replace('/', '_')
        tsi = tsi.replace('=', '')
        tsi = tsi.replace('\n', '')
        tsi = tsi.encode()
        tsi = tsi + '.'.encode('ascii') + base64.b64encode(
            binascii.unhexlify(hmac.new(SECRET_KEY.encode(), tsi, hashlib.sha256).hexdigest()))

        tsi = tsi.decode('ascii')
        tsi = tsi.replace('+', '-')
        tsi = tsi.replace('/', '_')
        tsi = tsi.replace('=', '')
        tsi = tsi.replace('\n', '')

        urget4 = "https://accounts.ea.com/connect/auth?authenticator_login_type=mobile_ea_account&client_id=simpsons4-android-client&nonce="
        urget44 = "&redirect_uri=nucleus:rest&release_type=prod&response_type=code lnglv_token&sig="
        data4 = requests.get(urget4 + nonce + urget44 + tsi, headers=HDRS)
        if data4.status_code != 200:
          print("Error getting lnglv_token")
          exit(-1)

        #print(data4.status_code)
        #print("CODE response 4")
        #print(data4.content)
        jsonResponse4 = data4.json()
        #print(jsonResponse4)
        mCode = jsonResponse4["code"]
        self.mPrevLnglv_token = jsonResponse4["lnglv_token"]


        # ACCESS TOKEN LOGIN
        h = HDRS.copy()
        h['X-Include-RT-Time'] = 'true'
        h['X-Suppress-Conflict'] = 'true'
        h['Content-Type'] = CT_URLENCODED
        urget5 = "https://accounts.ea.com/connect/token?client_id=simpsons4-android-client&client_secret="
        urget55 = "&code="
        urget555 = "&grant_type=add_authenticator&previous_access_token="
        urget5555 = "&redirect_uri=nucleus:rest&release_type=prod&transaction_guid="
        data5 = urget5 + CLIENT_SECRET + urget55 + mCode + urget555 + acto + urget5555 + str(uuid.uuid4())
        s = requests.Session()
        data6 = s.post(data5, headers=h)
        if data6.status_code != 200:
          print("Error getting client token")
          exit(-1)

        jsonResponse5 = data6.json()

        self.doAuthWithToken(jsonResponse5['access_token'])
        print("Downloading town...")
        self.doLandDownload()
        print("Saving town...")
        self.saveWorldData()
        print("Downloading and saving currency data...")
        self.saveCurrencyData()
        self.pull_friends()


    def doAuthWithToken(self, token):
        print(f"Attempting to acquire authentication via token: {token}")
        URL_SIMPSONS = 'prod.simpsons-ea.com'
        CT_URLENCODED = 'application/x-www-form-urlencoded'
        CT_XML = 'application/xml'
        HDRS = {'Accept': '*/*', 'Accept-Encoding': 'gzip', 'Connection': None, 'User-Agent': None}
        self.mAccessToken = token
        self.headers["mh_auth_params"] = self.mAccessToken
        self.headers["nucleus_token"] = self.mAccessToken
        path = '/connect/tokeninfo'
        params = 'access_token=%s' % (self.mAccessToken)
        h = dict()
        h['X-Check-Underage'] = 'true'
        h['X-Include-Authenticators'] = 'true'
        h['Content-Type'] = CT_URLENCODED
        data = requests.get("https://accounts.ea.com/" + path + '?' + params, headers=h)
        if data.status_code != 200:
          print("Error getting tokeninfo")
          exit(-1)

        self.mAuthPidId = ''
        self.mAuthPidId_Anon = ''
        data = data.json()
        for a in data['authenticators']:
            if a['authenticator_type'] == 'NUCLEUS':
                self.mAuthPidId = a['authenticator_pid_id']
            elif a['authenticator_type'] == 'AUTHENTICATOR_ANONYMOUS':
                self.mAuthPidId_Anon = a['authenticator_pid_id']

        path = '/proxy/identity/links'
        params = 'personaNamespace=gsp-redcrow-simpsons4'
        h = HDRS.copy()
        h['Authorization'] = 'Bearer ' + self.mAccessToken
        data = requests.get("https://gateway.ea.com" + path + '?' + params, headers=h)
        if data.status_code != 200:
          print("Error getting proxy id link")
          exit(-1)

        data = data.json()
        self.mPersonaId = ''
        self.mPersonaId_Anon = ''
        for m in data['pidGamePersonaMappings']['pidGamePersonaMapping']:
            if m['pidId'] == self.mAuthPidId:
                self.mPersonaId = m['personaId']
            elif m['pidId'] == self.mAuthPidId_Anon:
                self.mPersonaId_Anon = m['personaId']

        path = '/connect/tokeninfo'
        params = 'access_token=%s' % (self.mAccessToken)
        h = HDRS.copy()
        h['Content-Type'] = CT_URLENCODED
        data = requests.get("https://accounts.ea.com" + path + '?' + params, headers=h)
        if data.status_code != 200:
          print("Error connect tokeninfo")
          exit(-1)

        data = data.json()

        path = '/mh/users'
        params = "appVer=2.2.0&appLang=en&application=nucleus&applicationUserId=%s" % self.mAuthPidId
        h = self.headers.copy()
        h['Content-Type'] = CT_XML
        data = requests.get("https://prod.simpsons-ea.com" + path + '?' + params, True, headers=h)

        path = "/proxy/identity/pids/%s/personas" % self.mAuthPidId
        h = HDRS.copy()
        h['Accept'] = "*/*"
        h['Authorization'] = 'Bearer ' + self.mAccessToken
        h['X-Expand-Results'] = 'true'
        data = requests.get("https://gateway.ea.com" + path, headers=h)

        path = '/mh/users'
        ccsid = str(uuid.uuid4())
        self.mCcsid = ccsid
        params = "appVer=2.2.0&appLang=en&application=nucleus&applicationUserId=%s" % self.mAuthPidId
        h = self.headers.copy()
        h['Transfer-Encoding'] = 'chunked'
        h["currentClientSessionId"] = ccsid
        h['Accept'] = '*/*'
        h['Transfer-Encoding'] = 'chunked'
        h['Content-Type'] = CT_XML
        h['mh_auth_method'] = 'nucleus'
        h['mh_client_datetime'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S:000')
        h['currentClientSessionId'] = str(uuid.uuid4())
        h["mh_client_flag"] = "2"
        h['Content-Type'] = CT_XML
        data = self.doRequest("PUT", CT_XML, URL_SIMPSONS, path + '?' + params, True, hdrs=h)
        if "<error code=\"404\" type=\"NO_SUCH_RESOURCE\" field=\"token\" severity=\"INFO\"/>".encode() in data:
            path = '/mh/users'
            ccsid = str(uuid.uuid4())
            self.mCcsid = ccsid
            params = "appVer=2.2.0&appLang=en&application=nucleus&applicationUserId=%s" % self.mAuthPidId
            h = self.headers.copy()
            h['Transfer-Encoding'] = 'chunked'
            h["currentClientSessionId"] = ccsid
            h['Accept'] = '*/*'
            h['Transfer-Encoding'] = 'chunked'
            h['Content-Type'] = CT_XML
            h['mh_auth_params'] = self.mPrevLnglv_token
            h['nucleus_token'] = self.mPrevLnglv_token
            h['mh_auth_method'] = 'nucleus'
            h['mh_client_datetime'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S:000')
            h['currentClientSessionId'] = str(uuid.uuid4())
            h["mh_client_flag"] = "2"
            h['Content-Type'] = CT_XML
            data = self.doRequest("PUT", CT_XML, URL_SIMPSONS, path + '?' + params, True, hdrs=h)

            urm = AuthData_pb2.UsersResponseMessage()
            urm.ParseFromString(data)
            if urm.user.userId == '':
                return
        else:
            urm = AuthData_pb2.UsersResponseMessage()
            urm.ParseFromString(data)
            if urm.user.userId == '':
                return

        self.mUid = urm.user.userId
        self.mSession = urm.token.sessionKey

        h = self.headers.copy()
        h["Content-Type"] = "application/x-protobuf"
        h["mh_client_flag"] = "2"
        h["mh_auth_method"] = "nucleus"
        h["mh_auth_params"] = self.mAccessToken
        h["nucleus_token"] = self.mAccessToken
        h["mh_client_version"] = self.mMhClientVersion
        h["currentClientSessionId"] = self.mCcsid
        h["mh_uid"] = self.mUid
        h["mh_session_key"] = self.mSession
        h["target_land_id"] = self.mUid
        ts = datetime.datetime.today().isoformat(' ')
        h["mh_client_datetime"] = ts
        ts = ts + ' - ' + self.mMhClientVersion
        ts = ts + ' - ' + self.mSession

        ts = ts + ' - WARNING: Expected ID 81288208, but found ' + MHCODE + '. Found at 1495502718'
        ts = ts + chr(AES.block_size - len(ts) % AES.block_size) * (AES.block_size - len(ts) % AES.block_size)
        self.mhcrc = base64.b64encode(
            AES.new(MHHASH, AES.MODE_ECB).encrypt(ts.encode('ascii'))).decode()
        h["mh_crc"] = self.mhcrc

        wltr = WholeLandTokenData_pb2.WholeLandTokenRequest()
        wltr.requestId = str(uuid.uuid4())
        path = "/mh/games/bg_gameserver_plugin/protoWholeLandToken/%s/" % self.mUid
        datas = wltr.SerializeToString()
        data = requests.post("https://prod.simpsons-ea.com" + path, datas, True, headers=h)
        if "RESOURCE_ALREADY_EXISTS".encode() in data.content:
            wltr = WholeLandTokenData_pb2.WholeLandTokenRequest()
            wltr.requestId = str(uuid.uuid4())
            path = "/mh/games/bg_gameserver_plugin/protoWholeLandToken/%s/?force=1" % self.mUid
            datas = wltr.SerializeToString()
            data = requests.post("https://prod.simpsons-ea.com" + path, datas, True, headers=h)

        #print(data.content)
        wltr = WholeLandTokenData_pb2.WholeLandTokenRequest()
        wltr.ParseFromString(data.content)
        self.mUpdateToken = wltr.requestId
        self.headers["land-update-token"] = self.mUpdateToken
        self.mLogined = True
        self.headers["AuthToken"] = self.mAccessToken


    def doRequest(self, method, content_type, host, path, keep_alive=False, body=[], uncomressedLen=-1, hdrs={}):
        # # print("\n=============================================================================")
        url = ("https://%s%s" % (host, path)).encode('utf-8')
        if len(hdrs) != 0:
            headers = hdrs
        else:
            headers = self.headers.copy()
            if uncomressedLen > -1:
                headers["Content-Encoding"] = "gzip"
                headers["Uncompressed-Length"] = str(uncomressedLen)
                headers["Content-Length"] = str(len(body))
            headers["Content-Type"] = content_type
            headers["Content-Type"] = "application/x-protobuf"
            headers["mh_client_flag"] = "2"
            headers["mh_auth_method"] = "nucleus"
            headers["mh_auth_params"] = self.mAccessToken
            headers["nucleus_token"] = self.mAccessToken
            headers["mh_client_version"] = self.mMhClientVersion
            headers["currentClientSessionId"] = self.mCcsid
            headers["mh_uid"] = self.mUid
            headers["mh_session_key"] = self.mSession
            headers["target_land_id"] = self.mUid

        if keep_alive == True:
            ssn = self.mSesSimpsons if host == URL_SIMPSONS else self.mSesOther
        else:
            ssn = requests.Session()

        # mh_crc calculation
        if self.mSession != '':
            ts = datetime.datetime.today().isoformat(' ')
            headers["mh_client_datetime"] = ts
            ts = ts + ' - ' + self.mMhClientVersion
            ts = ts + ' - ' + self.mSession
            ts = ts + ' - WARNING: Expected ID 81288208, but found ' + MHCODE + '. Found at 1495502718'
            ts = ts + chr(AES.block_size - len(ts) % AES.block_size) * (AES.block_size - len(ts) % AES.block_size)
            headers["mh_crc"] = base64.b64encode(AES.new(MHHASH, AES.MODE_ECB).encrypt(ts.encode('ascii'))).decode()

        # prepare list of not needed headers
        forDel = []
        if len(hdrs) > 0:
            headers = {}
            for k, v in hdrs.items():
                if v is None:
                    forDel.append(k)
                else:
                    headers[k] = v

        # prepare request
        prepped = requests.Request(method, url=url, headers=headers, data=body).prepare()
        for h in forDel:
            if h in prepped.headers:
                del prepped.headers[h]

        r = ssn.send(prepped, verify=False)

        # reading response
        data = r.content

        if (len(data) == 0):
            logging.debug("no content")
        #else:
        #    logging.debug(data)
        return data

    def doLandDownload(self):
        data = self.doRequest("GET", CT_PROTOBUF, URL_SIMPSONS,
                              "/mh/games/bg_gameserver_plugin/protoland/%s/" % self.mUid, True)

        self.mLandMessage = LandData_pb2.LandMessage()
        self.mLandMessage.ParseFromString(data)

    def saveWorldData(self):
        if not os.path.exists("towns"):
          os.makedirs("towns")
        self.town_filename = os.path.join("towns", self.mEmail)
        if self.mLandMessage.HasField("friendData"):
          if self.mLandMessage.friendData.HasField("name"):
            self.town_filename = os.path.join(
                                  "towns", self.mLandMessage.friendData.name
                                 )
          
        with open(self.town_filename, "wb") as f:
            f.write(self.mLandMessage.SerializeToString())

    def saveCurrencyData(self):
        self.getCurrencyData()
        data = self.doRequest("GET", "application/x-protobuf", "prod.simpsons-ea.com"
                              , "/mh/games/bg_gameserver_plugin/protocurrency/%s/" % self.mUid, True);
        currdat = PurchaseData_pb2.CurrencyData()
        currdat2 = currdat.ParseFromString(data)
        with open(f"{self.town_filename}.currency", "wb") as f:
            f.write(data)

    def getCurrencyData(self):
        if self.mLandMessageExtra == None:
            self.mLandMessageExtra = LandData_pb2.ExtraLandMessage()
        return self.mLandMessageExtra

    def get_friends(self) -> dict:
      """Pull's the user's friends list"""

      # Make the request
      print("Getting friends list...")

      data = self.doRequest("GET", "application/x-protobuf", "prod.simpsons-ea.com",
                            "/mh/games/bg_gameserver_plugin/friendData/origin", True);

      
      # Load the protobuf
      req = GetFriendData_pb2.GetFriendDataResponse()
      req.ParseFromString(data)
      
      # Parse the protobuf into friend-land mapping
      friends = {}
      for friend in req.friendData:
        if not friend.HasField("friendId") or not friend.HasField("friendData"):
          print("skipping entry with missing friendId or friendData")
          continue
        land_id = friend.friendId      # this is the land_id
        friend_data = friend.friendData
        friend_name = land_id
        if not friend_data.HasField("name"):
          print(f"{land_id} is missing a name. Using land_id as the name")
        else:
          friend_name = friend_data.name

        friends[friend_name] = land_id
        print(f"Found friend: {friend_name}")       
      # Return the friend-land map
      return friends

    def pull_land(self, land_id: str, username: str) -> bool:
      """Downloads the land for the given user. Saves contents to disk."""

      # Start by downloading the LandData 
      print(f"Downloading {username}'s land (land_id: {land_id})")

      data = self.doRequest("GET", "application/x-protobuf", "prod.simpsons-ea.com",
                            f"/mh/games/bg_gameserver_plugin/protoland/{land_id}/", True)


      if not data:
        print(f"Error getting {username}'s land.")
        return False        

      filename = os.path.join("towns", username)
      with open(filename, "wb") as f:
        f.write(data)
 

      return True

      
    def pull_friends(self) -> bool:
      
      friends = self.get_friends()
      if not friends:
        print("You have no friends or there was an error.")
        return False
        
      for friend_name in friends:
        if not self.pull_land(friends[friend_name], friend_name):
          print(f"Failure getting {friend_name}'s land. Skipping.")
   
          
if __name__ == "__main__":
  TSTO()
