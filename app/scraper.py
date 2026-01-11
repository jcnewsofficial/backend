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

        # 1. Scrape Headline & Image
        headline_tag = soup.find('h1') or soup.find('meta', property='og:title')
        headline = headline_tag.get('content') if headline_tag and headline_tag.name == 'meta' else headline_tag.get_text() if headline_tag else "Unknown Headline"

        img_tag = soup.find('meta', property='og:image')
        image_url = img_tag.get('content') if img_tag else None

        # 2. Extract Body Text
        all_paragraphs = soup.find_all('p')
        full_text = " ".join([p.get_text() for p in all_paragraphs[:8]])

        # 3. AI Categorization & Summarization
        # We strictly define the allowed categories in the prompt
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a news classifier. Your tasks are:"
                        "1. Identify if the text is an Advertisement, Product Review, or Shopping Guide. If so, set 'is_ad': true."
                        "2. If it is real news, classify it into EXACTLY ONE of these categories: "
                        "'World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'General'. "
                        "   - If it doesn't fit the first 6, use 'General'."
                        "3. Provide 3 short, punchy bullet points summarizing the story."
                        "Return JSON: {'is_ad': bool, 'category': string, 'bullets': [str]}"
                    )
                },
                {"role": "user", "content": f"Headline: {headline}\n\nText: {full_text[:2000]}"}
            ],
            response_format={ "type": "json_object" }
        )

        result = json.loads(response.choices[0].message.content)

        if result.get("is_ad") is True:
            return None

        # Validate category just in case AI hallucinates
        valid_categories = ['World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'General']
        category = result.get("category", "General")
        if category not in valid_categories:
            category = "General"

        return {
            "headline": headline.strip(),
            "image_url": image_url,
            "category": category,  # <--- This is now the AI-determined category
            "bullets": result.get("bullets", [])[:3]
        }

    except Exception as e:
        print(f"AI Filtering error for {url}: {e}")
        return None
