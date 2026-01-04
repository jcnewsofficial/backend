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
    # 1. Fetch HTML
    headers = {'User-Agent': 'Mozilla/5.0'}
    res = requests.get(url, headers=headers)
    soup = BeautifulSoup(res.text, 'html.parser')

    # 2. Extract Data
    headline = soup.find('h1').get_text().strip()
    # Try to find the first image in the article
    img_tag = soup.find('meta', property="og:image")
    image_url = img_tag['content'] if img_tag else "https://example.com/default-capy.jpg"
    
    # Get main text content
    paragraphs = soup.find_all('p')
    full_text = " ".join([p.text for p in paragraphs[:5]])

    # 3. AI Processing
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{
            "role": "system", 
            "content": "You are a news editor. Summarize the following news into exactly 3 bullet points. Keep each point under 15 words."
        }, {"role": "user", "content": full_text}]
    )
    
    # Split AI response into a list of 3 strings
    raw_bullets = response.choices[0].message.content.strip()
    bullets = [b.strip("- ").strip() for b in raw_bullets.split('\n') if b.strip()][:3]

    return {
        "headline": headline,
        "image_url": image_url,
        "bullets": bullets
    }
