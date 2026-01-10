import requests
from bs4 import BeautifulSoup
from openai import OpenAI
import os
from dotenv import load_dotenv  # <--- THIS IS THE MISSING LINE

# Load variables from .env
load_dotenv()

# Get the key from the environment
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def auto_parse_news(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return None

        soup = BeautifulSoup(response.content, 'html.parser')

        # --- 1. Resilient Headline Extraction ---
        # Try H1 first, then OpenGraph tags (standard for NYT/BBC)
        headline = None
        headline_tag = soup.find('h1') or soup.find('meta', property='og:title')

        if headline_tag:
            # If it's a meta tag, get the 'content' attribute; otherwise get_text
            headline = headline_tag.get('content') if headline_tag.name == 'meta' else headline_tag.get_text()

        if not headline or len(headline.strip()) < 5:
            return None # Skip if no valid headline

        # --- 2. Resilient Image Extraction ---
        image_url = None
        # Look for the high-quality Social Media image first
        img_tag = soup.find('meta', property='og:image') or soup.find('meta', name='twitter:image')
        if img_tag:
            image_url = img_tag.get('content')

        # --- 3. Smart Bullet Point Extraction ---
        # Instead of just looking for <li>, we look for the main body paragraphs
        # and take the first 3 as "bullets"
        bullets = []
        # Common article body tags
        body_parts = soup.find_all(['p', 'li'], limit=15)
        for p in body_parts:
            text = p.get_text().strip()
            # Only take meaningful sentences (between 40 and 250 characters)
            if 40 < len(text) < 250 and not any(x in text.lower() for x in ['subscribe', 'cookie', 'follow us']):
                bullets.append(text)
            if len(bullets) >= 3: break

        # Fallback if no bullets found
        if not bullets:
            bullets = ["Click the link to read the full coverage of this developing story."]

        return {
            "headline": headline.strip(),
            "image_url": image_url,
            "bullets": bullets
        }

    except Exception as e:
        print(f"Parsing error for {url}: {e}")
        return None
