import requests
from api.models import PlatformType

def detect_platform(domain: str)-> PlatformType :
    try :
        url=f"https://{domain}"
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        reponse = requests.get(url, headers=headers)
        if 'shopify' in reponse.text.lower():
            return PlatformType.SHOPIFY
        if 'wix' in reponse.text.lower():
            return PlatformType.WIX
        if 'wp-content' in reponse.text.lower():
            return PlatformType.WORDPRESS
        return PlatformType.CUSTOM
    except Exception as e:
        return PlatformType.UNKNOWN

