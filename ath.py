
from getpass import getpass
import requests , json , re , base64

def calculate_elo(tier , progress):
    if tier >= 24:
        return 2100 + progress
    else:
        return ((tier *100) -300) + progress

class ath:
    def __init__(self, region="ap", auth={ "username": "", "password": "" }):
        self.region = region
        self.auth = auth
        self.se = requests.Session()
        self.ClientVersion = 'release-05.00-shipping-6-725355'
        self.ClientPlatform = {
            'platformType': "PC",
            'platformOS': "Windows",
            'platformOSVersion': "10.0.19042.1.256.64bit",
            'platformChipset': "Unknown",
            }

        with open('data.json', 'r' , encoding='utf-8') as f:
            try: 
                data = json.loads(f.read())
                data['headers']
                self.user_id = data['user_id']
                self.data = data
            except:
                self.authorize()
                

        self.url()
        

    def authorize(self):
        url = 'https://auth.riotgames.com/api/v1/authorization/'
        se = self.se

        data = {
        "client_id": "ritoplus",
        "nonce": "nuckles",
        "redirect_uri": "http://localhost/redirect",
        "response_type": "token id_token"
        }

        headers = {

        }

        se.post(url, json= data , headers=headers)

        data = {
            "language": "en_US",
            "password": self.auth['password'],
            # "region": null,
            "type": "auth",
            "username": self.auth['username']
        }

        r = se.put(url, json= data, headers=headers)
        data = r.json()
        pattern = re.compile('access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)')
        data = pattern.findall(data['response']['parameters']['uri'])[0]
        access_token = data[0]
        # print('Access Token: ' + access_token)

        headers = {
            'Authorization': f'Bearer {access_token}',
        }

        r = se.post('https://entitlements.auth.riotgames.com/api/token/v1', headers=headers, json={})
        data = r.json()
        # print(data)
        entitlements_token = data['entitlements_token']
        # print('_'*50)
        # print('Entitlements Token: ' + entitlements_token)

        r = se.post('https://auth.riotgames.com/userinfo', headers=headers, json={})
        data = r.json()
        # print(data)
        user_id = data['sub']
        # print('User ID: ' + user_id)
        headers['X-Riot-Entitlements-JWT'] = entitlements_token
        data = {'headers': headers, 'user_id': user_id}
        self.data = data
        self.user_id = data['user_id']
        data_js = json.dumps(data)
        with open('data.json', 'w', encoding='utf-8') as f:
            f.write(data_js)
        print('connect')
        self.se = se

    def generate_headers(self):
        headers = self.data['headers']
        headers['X-Riot-ClientVersion'] = self.ClientVersion
        client = json.dumps( self.ClientPlatform)
        str_bytes = client.encode('ascii')
        str_base64 = base64.b64encode(str_bytes)
        base64_str = str_base64.decode('ascii')
        headers['X-Riot-ClientPlatform'] = base64_str
        return headers

    def url(self):
        region = self.region
        self.PlayerData = f'https://pd.{region}.a.pvp.net'
        self.PartyService = f'https://glz-{region}-1.{region}.a.pvp.net'
        self.ShareData = f'https://shared.{region}.a.pvp.net'

    def requests_method(self , method , url , headers = None , body = None):
        se = self.se
        method = method.upper()
        if method == 'GET':
            r = se.get(url, headers = headers, json= body)
        elif method == 'POST':
            r = se.post(url, headers = headers, json = body)
        elif method == 'PUT':
            r = se.put(url, headers = headers, json = body)
        
        json_ = r.json()
        if r.status_code == 400:
            self.authorize()
            return self.requests_method(method , url, headers, body)
        
        return r.json()

    def getPlayerMMR(self, user_id):

        url = f'{self.PlayerData}/mmr/v1/players/{user_id}'
        r = self.requests_method('get', url, self.generate_headers())
        return r
    

    def no(self):
        pass

    def getMMR_ELO(self, user_id):
        url = f'{self.PlayerData}/mmr/v1/players/{user_id}/competitiveupdates?startIndex=0&endIndex=20'
        r = self.requests_method('get', url , self.generate_headers())

        match = r['Matches']
        for game in match:
            if game['RankedRatingAfterUpdate'] != 0:
                currentRP = game['RankedRatingAfterUpdate']
                rankNumber = game['TierAfterUpdate']
                break 

        return (rankNumber * 100) - 300 + currentRP
        


    

if __name__ == '__main__':
    user = input("username: ")
    password = input("password: ")

    m = ath(auth={"username": user, "password": password})
    r = m.getMMR_ELO(m.user_id)

    print("ElO:", r)