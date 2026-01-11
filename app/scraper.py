import requests
from bs4 import BeautifulSoup
from openai import OpenAI
import os
from dotenv import load_dotenv  # <--- THIS IS THE MISSING LINE
import json
import trafilatura

# Load variables from .env
load_dotenv()

# Get the key from the environment
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def auto_parse_news(url):
    try:
        # 1. Use Trafilatura to download and extract the MAIN text
        # This handles JS-heavy sites and removes ads/navbars automatically
        downloaded = trafilatura.fetch_url(url)

        if not downloaded:
            # Fallback for some strict sites: Try standard requests with browser headers
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    downloaded = response.text
            except:
                return None

        if not downloaded:
            return None

        # Extract clean text using Trafilatura (Best in class for news)
        full_text = trafilatura.extract(downloaded, include_comments=False, include_tables=False)

        # If extraction failed, skip this article
        if not full_text or len(full_text) < 200:
            return None

        # 2. Extract Metadata (Image & Headline) manually or via Trafilatura
        # We still use BS4 for metadata because it allows fine-grained control over OG tags
        soup = BeautifulSoup(downloaded, 'html.parser')

        headline_tag = soup.find('meta', property='og:title') or soup.find('h1')
        headline = headline_tag.get('content') if headline_tag and headline_tag.name == 'meta' else (headline_tag.get_text() if headline_tag else "Unknown Headline")

        img_tag = soup.find('meta', property='og:image')
        image_url = img_tag.get('content') if img_tag else None

        # 3. AI Categorization & Summarization
        # We send the CLEAN text to the AI now, so the results will be much better
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a news classifier. Tasks:"
                        "1. If text is an Ad, Shopping Guide, or Product Review, set 'is_ad': true."
                        "2. Classify into ONE: 'World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'Science', 'General'. "
                        "3. Provide 3 short, punchy bullet points (max 15 words each) summarizing the story."
                        "Return JSON: {'is_ad': bool, 'category': string, 'bullets': [str]}"
                    )
                },
                {"role": "user", "content": f"Headline: {headline}\n\nText: {full_text[:3000]}"} # Limit to 3000 chars to save tokens
            ],
            response_format={ "type": "json_object" }
        )

        result = json.loads(response.choices[0].message.content)

        if result.get("is_ad") is True:
            return None

        valid_categories = ['World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'Science', 'General']
        category = result.get("category", "General")
        if category not in valid_categories:
            category = "General"

        return {
            "headline": headline.strip(),
            "image_url": image_url,
            "category": category,
            "bullets": result.get("bullets", [])
        }

    except Exception as e:
        print(f"Scraper Error for {url}: {e}")
        return None
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
