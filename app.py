from flask import Flask, render_template, request
import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
# Initialize Flask app
app = Flask(__name__)

# Set up the Google API Key
os.environ["GOOGLE_API_KEY"] = os.getenv("API_KEY")
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-1.5-flash")

def url_detection(url):
    prompt = f"""
    You are an advanced AI model specializing in URL security classification. Analyze the given URL and classify it as one of the following categories:

    1. Benign**: Safe, trusted, and non-malicious websites such as google.com, wikipedia.org, amazon.com.
    2. Phishing**: Fraudulent websites designed to steal personal information. Indicators include misspelled domains (e.g., paypa1.com instead of paypal.com), unusual subdomains, and misleading content.
    3. Malware**: URLs that distribute viruses, ransomware, or malicious software. Often includes automatic downloads or redirects to infected pages.
    4. Defacement**: Hacked or defaced websites that display unauthorized content, usually altered by attackers.

    **Example URLs and Classifications:**
    - **Benign**: "https://www.microsoft.com/"
    - **Phishing**: "http://secure-login.paypa1.com/"
    - **Malware**: "http://free-download-software.xyz/"
    - **Defacement**: "http://hacked-website.com/"

    **Input URL:** {url}

    **Output Format:**  
    - Return only a string class name
    - Example output for a phishing site:  

    Analyze the URL and return the correct classification (Only name in lowercase such as benign etc.
    Note: Don't return empty or null, at any cost return the corrected class
    """

    response = model.generate_content(prompt)
    return response.text if response else "Detection failed."

def fake_news_detection(text):
    prompt = f"""
    You are an advanced AI model specializing in text analysis. Analyze the given text and classify it as one of the following categories:

    1. True**: The information is accurate and verified.
    2. Fake**: The information is false or misleading.

    **Example Texts and Classifications:**
    - **True**: "The Earth revolves around the Sun."
    - **Fake**: "The Earth is flat."

    **Input Text:** {text}

    **Output Format:**  
    - Return only a string class name
    - Example output for fake news:  

    Analyze the text and return the correct classification (Only name in lowercase such as true or fake).
    Note: Don't return empty or null, at any cost return the corrected class
    """

    response = model.generate_content(prompt)
    return response.text if response else "Detection failed."

# Routes

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(("http://", "https://")):
        return render_template("index.html", message="Invalid URL format.", input_url=url)

    classification = url_detection(url)
    return render_template("index.html", input_url=url, predicted_class=classification)

@app.route('/detect_fake_news', methods=['POST'])
def detect_fake_news():
    text = request.form.get('text', '').strip()

    if not text:
        return render_template("index.html", message="Text cannot be empty.", input_text=text)

    classification = fake_news_detection(text)
    return render_template("index.html", input_text=text, predicted_class=classification)

if __name__ == '__main__':
    app.run(debug=True)