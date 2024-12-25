# tsto_friend_puller
Tool for downloading your friends' The Simpsons: Tapped Out towns


# How to use

You'll need mitmproxy (https://mitmproxy.org/) installed on a computer and setup with your phone/tablet. Once you have that running, open your TSTO game.  Visit a friend's world. The mitmproxy should have a lot of requests pop up during this. Do not close out of your game at this point. 

In the mitmproxy logs, look for this URL:
  

    https://prod.simpsons-ea.com/mh/games/bg_gameserver_plugin/friendData/origin

     
      
Under the Request tab (after you click on that URL in the list), copy the entire
contents of the headers into a text file called "headers.txt". The following is
an example of what the file should look like:
  

    Host: prod.simpsons-ea.com
    Accept: */*
    Content-Type: application/xml; charset=UTF-8
    mh_auth_params: QVQxAAAAAAfhalskjdfhlaksjdaksjdfpZnZ2
    mh_client_version: iphone_bg_gameserver_plugin_4.69.5
    client_version: 4.69.5
    server_api_version: 4.0.0
    EA-SELL-ID: 851766
    mh_auth_method: nucleus
    Accept-Encoding: gzip
    Connection: Keep-Alive
    mh_client_datetime: 2024-12-25 00:38:58.743575
    mh_crc: /WV6w5JouVA6hZdppteZeY3assadfljhasdfhlaskjdfhsdljfh8FRz+rBDDGWDDig=
    mh_client_flag: 2
    nucleus_token: QVQASLKSD832VvdskdjfhlaksjjU5OTAxOnJpZnZ2
    platform: ios
    os_version: 18.1.1
    hw_model_id: 4 16.2
    data_param_1: 3456787846
    old_auth_params: 8232347293479
    currentClientSessionId: D8BAAAA4-BB7E-4DDD-9FED-26329505FCBA
    mh_session_key: d7cd20580274987cfdf34bd
    mh_uid: 000637314982734091827349334368923
    target_land_id: 3104985720349857586239603437539334368784371209487123323

Once you have that file created, run this script by executing: python friend_puller.py. It will save any friend's town that it was able to download to the same directory as the script with the friend's username as its name and .landproto as its extension.
