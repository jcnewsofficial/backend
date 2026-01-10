import requests
from bs4 import BeautifulSoup
from openai import OpenAI
import os
from dotenv import load_dotenv  # <--- THIS IS THE MISSING LINE
import json

# Load variables from .env
load_dotenv()

# Get the key from the environment
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def auto_parse_news(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200: return None

        soup = BeautifulSoup(response.content, 'html.parser')

        # 1. Scrape Headline & Image (Standard Metadata)
        headline_tag = soup.find('h1') or soup.find('meta', property='og:title')
        headline = headline_tag.get('content') if headline_tag.name == 'meta' else headline_tag.get_text()

        img_tag = soup.find('meta', property='og:image')
        image_url = img_tag.get('content') if img_tag else None

        # 2. Extract Body Text (First 1500 characters is usually enough for AI)
        all_paragraphs = soup.find_all('p')
        full_text = " ".join([p.get_text() for p in all_paragraphs[:8]])

        # 3. AI Gatekeeper & Summarizer
        # We ask for JSON so it's easy for Python to read the 'is_ad' flag
        response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an elite news editor for a hard-news application. "
                    "Your job is to filter out any content that is a: "
                    "1. Product Review or Hands-on (e.g., 'Review: Fujifilm X-E5'). "
                    "2. Product Roundup or Buying Guide (e.g., 'Best Mirrorless Cameras'). "
                    "3. Sponsored post or Advertisement. "
                    "4. Shopping deal or 'Price Drop' announcement. "

                    "Strict Rule: If the article's primary purpose is to evaluate a consumer product "
                    "or encourage a purchase, set 'is_ad' to true. "

                    "If it is genuine news (politics, tech industry trends, science, etc.), "
                    "provide 3 concise bullet points. "
                    "Return ONLY a JSON object: {'is_ad': bool, 'reason': string, 'bullets': []}"
                )
            },
            {"role": "user", "content": f"Headline: {headline}\n\nText: {full_text}"}
        ],
        response_format={ "type": "json_object" }
        )

        result = json.loads(response.choices[0].message.content)

        # Logic to skip
        if result.get("is_ad") is True:
            # Optional: Log the reason why the AI rejected it for debugging
            print(f"REJECTED ({result.get('reason')}): {headline[:50]}")
            return None

        return {
            "headline": headline.strip(),
            "image_url": image_url,
            "bullets": result.get("bullets", [])[:3]
        }

    except Exception as e:
        print(f"AI Filtering error for {url}: {e}")
        return None
