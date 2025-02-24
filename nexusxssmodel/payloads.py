import base64
import html
import random
import string

class PayloadObfuscator:
    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
        
    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def html_entities(payload: str) -> str:
        return html.escape(payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
    
    @staticmethod
    def add_random_spaces(payload: str) -> str:
        chars = list(payload)
        for i in range(len(chars)-1, 0, -1):
            if random.random() < 0.3:  # 30% chance
                chars.insert(i, ' ')
        return ''.join(chars)
    
    @staticmethod
    def add_nullbytes(payload: str) -> str:
        return payload.replace('<', '%00<%00')