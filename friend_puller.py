"""This script saves the worlds of your friends as well as your own.

You'll need mitmproxy (https://mitmproxy.org/) installed on a computer and setup
with your phone/tablet. Once you have that running, open your Simpson's game. 
Visit a friend's world. The mitmproxy should have a lot of requests pop up 
during this. Do not close out of your game at this point. 

In the mitmproxy logs, look for this URL:
  https://prod.simpsons-ea.com/mh/games/bg_gameserver_plugin/friendData/origin     
      
Under the Request tab (after you click on that URL in the list), copy the entire
contents of the headers into a text file called "headers.txt". The following is
an example of what the file should look like:
  
Host: prod.simpsons-ea.com
Accept: */*
Content-Type: application/xml; charset=UTF-8
mh_auth_params: QVQxOjasjkfhalskjdfhlaksjdaksjdfpZnZ2
mh_client_version: iphone_bg_gameserver_plugin_4.69.5
client_version: 4.69.5
server_api_version: 4.0.0
EA-SELL-ID: 851766
mh_auth_method: nucleus
Accept-Encoding: gzip
Connection: Keep-Alive
mh_client_datetime: 2024-12-25 00:38:58.743575
mh_crc: /WV6w5JouVA6hZdppteZeY3assadfljhasdfhlaskjdfhsdljfh8FRz+rLrSLKMxoJNig=
mh_client_flag: 2
nucleus_token: QVQxOjIuasdjklfhaslkdjfhlaksjjU5OTAxOnJpZnZ2
platform: ios
os_version: 18.1.1
hw_model_id: 4 16.2
data_param_1: 3456787846
old_auth_params: 8232347293479
currentClientSessionId: D8BAAAA4-BB7E-4DDD-9FED-26329505FCBA
mh_session_key: c7c120580274987cfdf34bc
mh_uid: 319637314982734091827349334368323
target_land_id: 31963752473046586239603437539334368784371209487123323

Once you have that file created, run this script. It will save any friend's town
that it was able to download to the same directory as the script with the
friend's username as its name and .landproto as its extension.

-tjac, 2024
"""

import requests

# The Simpsons: Tapped Out protobuffers
import GetFriendData_pb2


def parse_headers(filename: str) -> dict:
  header_dict = {}
  with open(filename, "r") as f:
    for l in f.readlines():
      # find the header name by locating the first colon
      split_pos = l.find(":")
      if split_pos < 0:
        print(f"Skipping: {l}")
        continue
      header_name = l[:split_pos].strip()
      header_value = l[split_pos+1:].strip()

      # Ignore certain headers:
      if header_name.lower() not in ["host", "accept", "content-type", 
                                     "accept-encoding", "connection"]:
        header_dict[header_name] = header_value

  return header_dict

def get_friends() -> dict:
  """Pull's the user's friends list"""

  # Import the headers we need for auth.
  headers = parse_headers("headers.txt")

  # This is the URL that will let us pull a list of our friends
  url = "https://prod.simpsons-ea.com/mh/games/bg_gameserver_plugin/friendData/origin"

  # Make the request
  print("Getting friends list...")
  r = requests.get(url, headers=headers)
  content_type = r.headers['content-type']
  if r.status_code != 200 or content_type != "application/x-protobuf":
    print(f"Error getting friend list. Status Code = {r.status_code}.")
    print(f"   Content-type = {content_type}")
    print(f"   Response: {r.content}")
    return {}
  
  # Load the protobuf
  req = GetFriendData_pb2.GetFriendDataResponse()
  req.ParseFromString(r.content)
  
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
    print(f"{friend_name} -> {land_id}")
    friends[friend_name] = land_id
   
  # Return the friend-land map
  return friends

def pull_land(land_id: str, username: str) -> bool:
  """Downloads the land for the given user. Saves contents to disk."""

  headers = parse_headers("headers.txt")

  # Start by downloading the LandData 
  print(f"Downloading {username}'s land (land_id: {land_id})")
  url = f"https://prod.simpsons-ea.com/mh/games/bg_gameserver_plugin/protoland/{land_id}/"
  r = requests.get(url, headers=headers)
  content_type = r.headers['content-type']
  if r.status_code != 200 or content_type != "application/x-protobuf":
    print(f"Error getting {username}'s land. Status Code = {r.status_code}.")
    print(f"   Content-type = {content_type}")
    print(f"   Response: {r.content}")
    return False

  land_file = open(f"{username}.landproto", "wb")
  land_file.write(r.content)
  land_file.close()


  # Get the currency data for the user
  print(f"Downloading {username}'s currency")
  url = f"https://prod.simpsons-ea.com/mh/games/bg_gameserver_plugin/protocurrency/{land_id}/"
  r = requests.get(url, headers=headers)
  content_type = r.headers['content-type']
  if r.status_code != 200 or content_type != "application/x-protobuf":
    print(f"Error getting {username}'s currency. Status Code = {r.status_code}.")
    print(f"   Content-type = {content_type}")
    print(f"   Response: {r.content}")
    return True     # this is a soft error since we already got the land proto.

  currency_file = open(f"{username}.currency", "wb")
  currency_file.write(r.content)
  currency_file.close()    

  return True

  
def pull_friends() -> bool:
  
  friends = get_friends()
  if not friends:
    print("You have no friends or there was an error.")
    return False
    
  for friend_name in friends:
    if not pull_land(friends[friend_name], friend_name):
      print("Failure getting {friend_name}'s land. Skipping.")
         

 

if __name__ == "__main__":
  pull_friends()


