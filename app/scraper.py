import requests
from bs4 import BeautifulSoup
from openai import OpenAI
import os
from dotenv import load_dotenv
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
        downloaded = trafilatura.fetch_url(url)

        if not downloaded:
            # Fallback for some strict sites
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    downloaded = response.text
            except:
                return None

        if not downloaded:
            return None

        # Extract clean text
        full_text = trafilatura.extract(downloaded, include_comments=False, include_tables=False)

        if not full_text or len(full_text) < 200:
            return None

        # 2. Extract Metadata
        soup = BeautifulSoup(downloaded, 'html.parser')

        headline_tag = soup.find('meta', property='og:title') or soup.find('h1')
        headline = headline_tag.get('content') if headline_tag and headline_tag.name == 'meta' else (headline_tag.get_text() if headline_tag else "Unknown Headline")

        img_tag = soup.find('meta', property='og:image')
        image_url = img_tag.get('content') if img_tag else None

        # 3. AI Categorization & Summarization
        # UPDATED PROMPT: Explicitly filters Podcasts/Audio/Video descriptions
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a strict news filter. Tasks:"
                        "1. Analyze the text. If it is an Advertisement, Shopping Guide, Product Review, "
                        "Podcast, Audio Transcript, Video Description (without full article text), or a generic Landing Page, "
                        "set 'is_ad': true."
                        "2. If it is a real text article, classify into ONE: 'World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'Science', 'General'. "
                        "3. Provide 3 short, punchy bullet points (max 15 words each) summarizing the story."
                        "Return JSON: {'is_ad': bool, 'category': string, 'bullets': [str]}"
                    )
                },
                {"role": "user", "content": f"Headline: {headline}\n\nText: {full_text[:3000]}"}
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
        # Fallback Logic (same strictness applied here)
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200: return None

            soup = BeautifulSoup(response.content, 'html.parser')

            headline_tag = soup.find('h1') or soup.find('meta', property='og:title')
            headline = headline_tag.get('content') if headline_tag and headline_tag.name == 'meta' else headline_tag.get_text() if headline_tag else "Unknown Headline"

            img_tag = soup.find('meta', property='og:image')
            image_url = img_tag.get('content') if img_tag else None

            all_paragraphs = soup.find_all('p')
            full_text = " ".join([p.get_text() for p in all_paragraphs[:8]])

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a strict news filter. Tasks:"
                            "1. If the text is an Advertisement, Product Review, Shopping Guide, "
                            "Podcast, Audio Transcript, or Video Summary, set 'is_ad': true."
                            "2. If real news, classify into: 'World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'General'. "
                            "3. Provide 3 short, punchy bullet points."
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

            valid_categories = ['World', 'Politics', 'Business', 'Tech', 'Sports', 'Entertainment', 'General']
            category = result.get("category", "General")
            if category not in valid_categories:
                category = "General"

            return {
                "headline": headline.strip(),
                "image_url": image_url,
                "category": category,
                "bullets": result.get("bullets", [])[:3]
            }

        except Exception as inner_e:
            print(f"Scraper Error for {url}: {e} -> Fallback Error: {inner_e}")
            return None
